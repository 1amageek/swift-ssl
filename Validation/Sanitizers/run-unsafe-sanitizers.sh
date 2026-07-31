#!/bin/sh

set -eu

toolchain_identifier="org.swift.64202607231a"
expected_compiler_commit="ef761e567dc94ee"
timeout_seconds=120
selected_sanitizer=all

usage() {
    echo "usage: $0 [--sanitizer asan|tsan|ubsan|all] [--timeout 1...120]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --sanitizer)
            if [ "$#" -lt 2 ]; then
                usage
                exit 2
            fi
            selected_sanitizer="$2"
            shift 2
            ;;
        --timeout)
            if [ "$#" -lt 2 ]; then
                usage
                exit 2
            fi
            timeout_seconds="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

case "$selected_sanitizer" in
    asan|tsan|ubsan|all)
        ;;
    *)
        usage
        exit 2
        ;;
esac

case "$timeout_seconds" in
    ''|*[!0-9]*)
        echo "timeout must be an integer number of seconds" >&2
        exit 2
        ;;
esac
if [ "$timeout_seconds" -lt 1 ] || [ "$timeout_seconds" -gt 120 ]; then
    echo "timeout must be between 1 and 120 seconds" >&2
    exit 2
fi

script_directory="$(CDPATH= cd "$(dirname "$0")" && pwd)"
repository_root="$(CDPATH= cd "$script_directory/../.." && pwd)"
cd "$repository_root"

for required_script in \
    scripts/check-sync-shutdown-in-deinit.sh \
    scripts/swift-test-timeout.sh
do
    if [ ! -x "$required_script" ]; then
        echo "Missing executable validation helper: $required_script" >&2
        exit 2
    fi
done

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

artifact_root=".test-artifacts/sanitizers"
guard_root=".test-artifacts/hang-guard"
guard_lock="$guard_root/.lock"
mkdir -p "$artifact_root" "$guard_root"
if ! mkdir "$guard_lock" 2>/dev/null; then
    echo "another guarded Swift test run is active" >&2
    exit 3
fi
trap 'rmdir "$guard_lock" 2>/dev/null || true' EXIT HUP INT TERM

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
artifact_directory="$artifact_root/$timestamp-$$"
mkdir -p "$artifact_directory"

scripts/check-sync-shutdown-in-deinit.sh Sources Tests

before_helpers="$artifact_directory/helpers-before.txt"
pgrep -x swiftpm-testing-helper 2>/dev/null | sort -n >"$before_helpers" || true
host_architecture="$(uname -m)"

run_sanitizer() {
    sanitizer_name="$1"
    address_enabled=NO
    thread_enabled=NO
    undefined_enabled=NO

    case "$sanitizer_name" in
        asan)
            address_enabled=YES
            ;;
        tsan)
            thread_enabled=YES
            ;;
        ubsan)
            undefined_enabled=YES
            ;;
    esac

    derived_data_path=".build/xcode-derived-data-sanitizers/$sanitizer_name"
    result_bundle="$artifact_directory/$sanitizer_name.xcresult"
    log_path="$artifact_directory/$sanitizer_name.log"

    echo "Running $sanitizer_name with a ${timeout_seconds}s external timeout"
    set +e
    TOOLCHAINS="$toolchain_identifier" \
        scripts/swift-test-timeout.sh "$timeout_seconds" \
        xcodebuild test \
        -scheme swift-ssl-Package \
        -destination "platform=macOS,arch=$host_architecture" \
        -derivedDataPath "$derived_data_path" \
        -resultBundlePath "$result_bundle" \
        -only-testing:SwiftSSLCoreTests \
        -only-testing:SwiftSSLCryptoTests \
        -parallel-testing-enabled NO \
        -jobs 2 \
        -enableAddressSanitizer "$address_enabled" \
        -enableThreadSanitizer "$thread_enabled" \
        -enableUndefinedBehaviorSanitizer "$undefined_enabled" \
        >"$log_path" 2>&1
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        {
            echo "sanitizer: $sanitizer_name"
            echo "command status: $status"
            echo "swift-related processes:"
            ps -axo pid,ppid,state,etime,command | rg 'swift|xcodebuild' || true
            echo "SwiftPM lock files:"
            find .build -name '*.lock' -print 2>/dev/null || true
        } >"$artifact_directory/$sanitizer_name.diag.txt"
        tail -n 240 "$log_path" >&2
        echo "$sanitizer_name failed; diagnostics: $artifact_directory" >&2
        exit "$status"
    fi

    after_helpers="$artifact_directory/$sanitizer_name-helpers-after.txt"
    pgrep -x swiftpm-testing-helper 2>/dev/null | sort -n >"$after_helpers" || true
    if comm -13 "$before_helpers" "$after_helpers" | rg -q '.'; then
        {
            echo "New swiftpm-testing-helper processes remained after $sanitizer_name"
            comm -13 "$before_helpers" "$after_helpers"
        } >"$artifact_directory/$sanitizer_name.diag.txt"
        echo "$sanitizer_name left a stale test helper; diagnostics: $artifact_directory" >&2
        exit 1
    fi

    summary_path="$artifact_directory/$sanitizer_name-summary.json"
    xcrun xcresulttool get test-results summary \
        --path "$result_bundle" \
        >"$summary_path"
    python3 - "$sanitizer_name" "$summary_path" <<'PYTHON'
import json
import sys


sanitizer_name = sys.argv[1]
with open(sys.argv[2], encoding="utf-8") as summary_file:
    summary = json.load(summary_file)

passed = summary.get("passedTests", 0)
failed = summary.get("failedTests", 0)
skipped = summary.get("skippedTests", 0)
runtime_warnings = summary.get("runtimeWarnings", [])
if (
    summary.get("result") != "Passed"
    or passed < 1
    or failed != 0
    or skipped != 0
    or runtime_warnings
):
    raise SystemExit(
        f"{sanitizer_name} result summary is not clean: "
        f"passed={passed}, failed={failed}, skipped={skipped}, "
        f"runtimeWarnings={len(runtime_warnings)}"
    )

print(f"{sanitizer_name}: {passed} tests passed with no runtime warnings")
PYTHON
}

printf '%s\n' "$compiler_version"
case "$selected_sanitizer" in
    asan)
        run_sanitizer asan
        ;;
    tsan)
        run_sanitizer tsan
        ;;
    ubsan)
        run_sanitizer ubsan
        ;;
    all)
        run_sanitizer asan
        run_sanitizer tsan
        run_sanitizer ubsan
        ;;
esac

echo "Sanitizer validation passed; artifacts: $artifact_directory"
