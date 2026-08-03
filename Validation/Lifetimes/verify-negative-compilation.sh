#!/bin/sh

set -eu

toolchain_identifier="org.swift.64202607231a"
expected_compiler_commit="ef761e567dc94ee"
wasi_sdk_identifier="swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm"
embedded_wasi_sdk_identifier="swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded"

script_directory="$(CDPATH= cd "$(dirname "$0")" && pwd)"
repository_root="$(CDPATH= cd "$script_directory/../.." && pwd)"
cd "$repository_root"

timeout_helper="scripts/swift-test-timeout.sh"
if [ ! -x "$timeout_helper" ]; then
    echo "Missing executable timeout helper: $timeout_helper" >&2
    exit 2
fi

swiftc_path="$(xcrun --toolchain "$toolchain_identifier" -f swiftc)"
compiler_version="$("$swiftc_path" -version 2>&1)"
case "$compiler_version" in
    *"Swift $expected_compiler_commit"*)
        ;;
    *)
        echo "Unexpected Swift compiler; expected commit $expected_compiler_commit" >&2
        printf '%s\n' "$compiler_version" >&2
        exit 2
        ;;
esac

wasi_configuration="$(
    TOOLCHAINS="$toolchain_identifier" xcrun swift sdk configure \
        "$wasi_sdk_identifier" --show-configuration 2>/dev/null
)"
embedded_wasi_configuration="$(
    TOOLCHAINS="$toolchain_identifier" xcrun swift sdk configure \
        "$embedded_wasi_sdk_identifier" --show-configuration 2>/dev/null
)"

configuration_value() {
    configuration="$1"
    key="$2"
    printf '%s\n' "$configuration" | sed -n "s/^$key: //p" | head -n 1
}

wasi_sdk_root="$(configuration_value "$wasi_configuration" sdkRootPath)"
wasi_resources="$(configuration_value "$wasi_configuration" swiftStaticResourcesPath)"
embedded_wasi_sdk_root="$(configuration_value "$embedded_wasi_configuration" sdkRootPath)"
embedded_wasi_resources="$(
    configuration_value "$embedded_wasi_configuration" swiftResourcesPath
)"

for required_path in \
    "$wasi_sdk_root" \
    "$wasi_resources" \
    "$embedded_wasi_sdk_root" \
    "$embedded_wasi_resources"
do
    if [ -z "$required_path" ] || [ ! -e "$required_path" ]; then
        echo "Unable to resolve a required Swift SDK path: $required_path" >&2
        exit 2
    fi
done

artifact_directory="$(mktemp -d "${TMPDIR:-/tmp}/swift-ssl-lifetimes.XXXXXX")"
trap 'rm -rf "$artifact_directory"' EXIT HUP INT TERM

core_sources="$(find Sources/SSLCore -name '*.swift' -type f | sort)"
common_flags='-O -wmo -parse-as-library -package-name swift_ssl -enable-experimental-feature NonescapableTypes -enable-experimental-feature LifetimeDependence -enable-experimental-feature InoutLifetimeDependence -enable-experimental-feature LifetimeDependenceMutableAccessors -enable-experimental-feature Lifetimes -enable-experimental-feature Volatile -emit-ir -module-name SSLLifetimeNegativeValidation'

compile_fixture() {
    target_label="$1"
    fixture_name="$2"
    expected_diagnostic="$3"
    shift 3

    fixture_path="Validation/Lifetimes/Fixtures/$fixture_name.swift"
    log_path="$artifact_directory/$target_label-$fixture_name.log"

    # The source list and common flags are repository-controlled and contain no spaces.
    # shellcheck disable=SC2086
    if "$timeout_helper" 30 \
        "$swiftc_path" $core_sources "$fixture_path" $common_flags "$@" \
        -o /dev/null >"$log_path" 2>&1
    then
        echo "$target_label/$fixture_name unexpectedly compiled" >&2
        exit 1
    fi

    if ! rg -F -q -- "$expected_diagnostic" "$log_path"; then
        echo "$target_label/$fixture_name failed for an unexpected reason" >&2
        cat "$log_path" >&2
        exit 1
    fi

    echo "$target_label/$fixture_name: expected diagnostic verified"
}

validate_target() {
    target_label="$1"
    shift

    compile_fixture \
        "$target_label" \
        EscapingBorrow \
        "requires that 'Span<UInt8>' conform to 'Escapable'" \
        "$@"
    compile_fixture \
        "$target_label" \
        TaskCapture \
        "lifetime-dependent variable 'bytes' escapes its scope" \
        "$@"
    compile_fixture \
        "$target_label" \
        MutableSpanCapture \
        "escaping closure captures 'inout' parameter 'destination'" \
        "$@"
    compile_fixture \
        "$target_label" \
        DoubleConsume \
        "'secret' consumed more than once" \
        "$@"
}

printf '%s\n' "$compiler_version"
validate_target native
validate_target \
    wasi \
    -target wasm32-unknown-wasip1 \
    -sdk "$wasi_sdk_root" \
    -resource-dir "$wasi_resources" \
    -static-stdlib
validate_target \
    embedded-wasi \
    -target wasm32-unknown-wasip1 \
    -sdk "$embedded_wasi_sdk_root" \
    -resource-dir "$embedded_wasi_resources" \
    -static-stdlib \
    -enable-experimental-feature Embedded

echo "All lifetime and ownership negative-compilation fixtures passed"
