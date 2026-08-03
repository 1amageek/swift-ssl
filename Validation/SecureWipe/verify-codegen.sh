#!/bin/sh

set -eu

toolchain_identifier="org.swift.64202607231a"
expected_compiler_commit="ef761e567dc94ee"
wasi_sdk_identifier="swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm"
embedded_sdk_identifier="swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded"
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

wasi_sdk_configuration="$(TOOLCHAINS="$toolchain_identifier" xcrun swift sdk configure "$wasi_sdk_identifier" --show-configuration 2>/dev/null)"
embedded_sdk_configuration="$(TOOLCHAINS="$toolchain_identifier" xcrun swift sdk configure "$embedded_sdk_identifier" --show-configuration 2>/dev/null)"
wasi_sdk_root="$(printf '%s\n' "$wasi_sdk_configuration" | sed -n 's/^sdkRootPath: //p' | head -n 1)"
wasi_resources="$(printf '%s\n' "$wasi_sdk_configuration" | sed -n 's/^swiftResourcesPath: //p' | head -n 1)"
embedded_sdk_root="$(printf '%s\n' "$embedded_sdk_configuration" | sed -n 's/^sdkRootPath: //p' | head -n 1)"
embedded_resources="$(printf '%s\n' "$embedded_sdk_configuration" | sed -n 's/^swiftResourcesPath: //p' | head -n 1)"

if [ -z "$wasi_sdk_root" ] || [ -z "$wasi_resources" ]; then
    echo "Unable to resolve Swift SDK: $wasi_sdk_identifier" >&2
    exit 1
fi
if [ -z "$embedded_sdk_root" ] || [ -z "$embedded_resources" ]; then
    echo "Unable to resolve Swift SDK: $embedded_sdk_identifier" >&2
    exit 1
fi

artifact_directory="$(mktemp -d)"
trap 'rm -rf "$artifact_directory"' EXIT HUP INT TERM
evidence_root=".test-artifacts/codegen"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_directory="$evidence_root/$timestamp-$$"
mkdir -p "$evidence_directory"
printf '%s\n' "$compiler_version" >"$evidence_directory/compiler-version.txt"
printf '%s\n' "$wasi_sdk_configuration" >"$evidence_directory/wasi-sdk-configuration.txt"
printf '%s\n' "$embedded_sdk_configuration" >"$evidence_directory/embedded-sdk-configuration.txt"

core_sources="$(find Sources/SSLCore -name '*.swift' -type f | sort)"
crypto_sources="$(find Sources/SSLCrypto -name '*.swift' -type f | sort)"
ownership_flags='-parse-as-library -package-name swift_ssl -enable-experimental-feature NonescapableTypes -enable-experimental-feature LifetimeDependence -enable-experimental-feature InoutLifetimeDependence -enable-experimental-feature LifetimeDependenceMutableAccessors -enable-experimental-feature Lifetimes'
core_common_flags="$ownership_flags -enable-experimental-feature Volatile -module-name SSLCore"
crypto_common_flags="$ownership_flags -module-name SSLCrypto"

case "${SWIFT_SSL_CODEGEN_OPTIMIZATION:-all}" in
    all)
        optimizations="-O -Osize"
        ;;
    -O|-Osize)
        optimizations="${SWIFT_SSL_CODEGEN_OPTIMIZATION}"
        ;;
    *)
        echo "SWIFT_SSL_CODEGEN_OPTIMIZATION must be -O, -Osize, or all" >&2
        exit 2
        ;;
esac

case "${SWIFT_SSL_CODEGEN_TARGET:-all}" in
    all|native|wasi|embedded-wasi)
        codegen_target="${SWIFT_SSL_CODEGEN_TARGET:-all}"
        ;;
    *)
        echo "SWIFT_SSL_CODEGEN_TARGET must be native, wasi, embedded-wasi, or all" >&2
        exit 2
        ;;
esac

validate_ir() {
    label="$1"
    whole_module_ir="$2"
    secret_bytes_ir="$3"
    secure_wipe_ir="$4"
    mode="$5"

    python3 - "$label" "$whole_module_ir" "$secret_bytes_ir" "$secure_wipe_ir" "$mode" <<'PYTHON'
import re
import sys
from pathlib import Path


label = sys.argv[1]
whole_module = Path(sys.argv[2]).read_text(encoding="utf-8")
secret_bytes = Path(sys.argv[3]).read_text(encoding="utf-8")
secure_wipe = Path(sys.argv[4]).read_text(encoding="utf-8")
mode = sys.argv[5]

sys.path.insert(0, "Validation/SecureWipe")
import verify_crypto_ir as validator

validator.verify_secret_bytes_ir(
    f"{label} SecretBytes source",
    secret_bytes,
    embedded=mode == "embedded",
)
validator.verify_secret_bytes_ir(
    f"{label} SecretBytes whole module",
    whole_module,
    embedded=mode == "embedded",
)


def function_bodies(ir, symbol_fragment):
    pattern = re.compile(
        r'^define[^\n]*"[^\n]*' + re.escape(symbol_fragment) + r'[^\n]*\n'
        r'(.*?\n})',
        re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(ir)
    if not matches:
        raise RuntimeError(f"{label}: missing production symbol {symbol_fragment}")
    return matches


def require_wipe_before_deallocation(ir, symbol_fragment):
    for body in function_bodies(ir, symbol_fragment):
        wipe_index = body.find("SecureWipeO5erase")
        deallocation_indexes = [
            index
            for index in (
                body.find("swift_slowDealloc"),
                body.find("call void @free"),
            )
            if index >= 0
        ]
        if wipe_index >= 0 and deallocation_indexes:
            if wipe_index < min(deallocation_indexes):
                return
    raise RuntimeError(
        f"{label}: {symbol_fragment} lacks wipe-before-deallocation order"
    )


def require_value_witness_cleanup(ir):
    try:
        require_wipe_before_deallocation(ir, "SecretBytesVwxx")
        return
    except RuntimeError:
        pass
    bodies = function_bodies(ir, "SecretBytesVwxx")
    if any("SecretBytesVfD" in body for body in bodies):
        return
    raise RuntimeError(
        f"{label}: SecretBytes value witness does not destroy through deinit"
    )


require_wipe_before_deallocation(secret_bytes, "SecretBytesVfD")
require_wipe_before_deallocation(whole_module, "SecretBytesVfD")

if mode == "embedded":
    require_wipe_before_deallocation(
        whole_module,
        "secureWipeFailureCleanupProbe",
    )
else:
    require_value_witness_cleanup(secret_bytes)
    require_value_witness_cleanup(whole_module)
    require_wipe_before_deallocation(
        secret_bytes,
        "SecretBytesV9byteCount16initializingWith",
    )
    require_wipe_before_deallocation(
        whole_module,
        "SecretBytesV9byteCount16initializingWith",
    )

print(f"{label}: production wipe and wipe-before-free order verified")
PYTHON

    python3 Validation/SecureWipe/verify_crypto_ir.py \
        --verify-wipe \
        "$label SecureWipe file" \
        "$secure_wipe_ir"
    python3 Validation/SecureWipe/verify_crypto_ir.py \
        --verify-wipe \
        "$label whole module" \
        "$whole_module_ir"

    python3 - "$label" "$secure_wipe_ir" "$whole_module_ir" <<'PYTHON'
import re
import sys
from pathlib import Path


label = sys.argv[1]
inputs = (
    ("SecureWipe file", Path(sys.argv[2]).read_text(encoding="utf-8")),
    ("whole module", Path(sys.argv[3]).read_text(encoding="utf-8")),
)


def function_bodies(ir, symbol_fragment):
    pattern = re.compile(
        r'^define[^\n]*"[^\n]*' + re.escape(symbol_fragment) + r'[^\n]*\n'
        r'(.*?\n})',
        re.MULTILINE | re.DOTALL,
    )
    return pattern.findall(ir)


for source, ir in inputs:
    for symbol_fragment, width in (
        ("eraseUInt16Words", 16),
        ("eraseUInt64Words", 64),
    ):
        bodies = function_bodies(ir, symbol_fragment)
        if not bodies:
            raise RuntimeError(
                f"{label} {source}: missing production symbol {symbol_fragment}"
            )
        if not any(
            re.search(rf"store(?: atomic)? volatile i{width} 0, ptr ", body)
            for body in bodies
        ):
            raise RuntimeError(
                f"{label} {source}: {symbol_fragment} lacks volatile i{width} zero store"
            )

print(f"{label}: UInt16 and UInt64 volatile wipe widths verified")
PYTHON
}

validate_crypto_ir() {
    label="$1"
    crypto_ir="$2"
    core_ir="$3"

    python3 Validation/SecureWipe/verify_crypto_ir.py \
        "$label" \
        "$crypto_ir" \
        "$core_ir"

    python3 - "$label" "$crypto_ir" <<'PYTHON'
import re
import sys
from pathlib import Path


label = sys.argv[1]
ir = Path(sys.argv[2]).read_text(encoding="utf-8")


def find_function_bodies(symbol_fragment):
    pattern = re.compile(
        r'^define[^\n]*"[^\n]*' + re.escape(symbol_fragment) + r'[^\n]*\n'
        r'(.*?\n})',
        re.MULTILINE | re.DOTALL,
    )
    return pattern.findall(ir)


def function_bodies(symbol_fragment):
    matches = find_function_bodies(symbol_fragment)
    if not matches:
        raise RuntimeError(f"{label}: missing production symbol {symbol_fragment}")
    return matches


def wipe_lines(body):
    return [
        line
        for line in body.splitlines()
        if "SecureWipeO5erase" in line
    ]


def has_byte_count(line, byte_count):
    return re.search(rf"i(?:32|64) {byte_count}\)", line) is not None


def object_derived_pointers(body):
    derived = {"%0"}
    lines = body.splitlines()
    changed = True
    while changed:
        changed = False
        for line in lines:
            match = re.search(
                r"^\s*(%[-.\w]+) = getelementptr[^\n]*"
                r"ptr (?:nonnull )?(%[-.\w]+),",
                line,
            )
            if match and match.group(2) in derived:
                if match.group(1) not in derived:
                    derived.add(match.group(1))
                    changed = True
    return derived


def wipe_pointer(line):
    match = re.search(
        r"SecureWipeO5erase[^\n]*"
        r"\(ptr (?:nonnull )?(%[-.\w]+), i(?:32|64) \d+\)",
        line,
    )
    return match.group(1) if match else None


def has_in_place_state_wipes(body):
    wipes = wipe_lines(body)
    derived_pointers = object_derived_pointers(body)
    wipe_pointers = [wipe_pointer(line) for line in wipes]
    return (
        len(wipes) >= 4
        and sum(has_byte_count(line, 32) for line in wipes) >= 2
        and sum(has_byte_count(line, 64) for line in wipes) >= 2
        and all(pointer in derived_pointers for pointer in wipe_pointers)
        and "alloca %T14SSLCrypto13SHA256ContextV" not in body
    )


deinit_verified = False
for body in function_bodies("HMACSHA256ContextStorageCfD"):
    deallocation_indexes = [
        index
        for index in (
            body.find("swift_deallocClassInstance"),
            body.find("call void @free"),
        )
        if index >= 0
    ]
    has_self_deallocation = (
        "swift_deallocClassInstance(ptr %0" in body
        or re.search(
            r"call void @free\(ptr (?:nonnull )?%0\)",
            body,
        )
    )
    if not deallocation_indexes or not has_self_deallocation:
        continue

    wipe_indexes = [body.find(line) for line in wipe_lines(body)]
    if (
        has_in_place_state_wipes(body)
        and max(wipe_indexes) < min(deallocation_indexes)
    ):
        deinit_verified = True
        break

    helper_call_pattern = re.compile(
        r'call swiftcc void @"([^"]*HMACSHA256ContextStorageC'
        r'[^"]*eraseSensitive[^"]*)"\(ptr swiftself %0\)'
    )
    for helper_call in helper_call_pattern.finditer(body):
        if helper_call.start() >= min(deallocation_indexes):
            continue
        helper_symbol = helper_call.group(1)
        if any(
            has_in_place_state_wipes(helper_body)
            for helper_body in function_bodies(helper_symbol)
        ):
            deinit_verified = True
            break
    if deinit_verified:
        break
if not deinit_verified:
    raise RuntimeError(
        f"{label}: stable HMAC backing is not wiped in place before deallocation"
    )


update_verified = False
for body in function_bodies("HMACSHA256ContextV6update"):
    forbidden_hot_path_operations = (
        "swift_allocObject",
        "swift_retain",
        "swift_release",
        "malloc(",
        "llvm.memcpy",
        "llvm.memmove",
    )
    if (
        "SHA256ContextV6update" in body
        and not any(
            operation in body
            for operation in forbidden_hot_path_operations
        )
    ):
        update_verified = True
        break
if not update_verified:
    raise RuntimeError(
        f"{label}: HMAC update contains allocation, reference traffic, or copying"
    )


key_setup_heap_operations = (
    "swift_allocObject",
    "swift_retain",
    "swift_release",
    "malloc(",
    "call void @free",
)


def basic_blocks(body):
    blocks = []
    block_name = None
    block_lines = []
    for line in body.splitlines():
        label_match = re.match(r"^([-.\w]+):", line)
        if label_match:
            if block_name is not None:
                blocks.append((block_name, "\n".join(block_lines)))
            block_name = label_match.group(1)
            block_lines = []
        elif block_name is not None:
            block_lines.append(line)
    if block_name is not None:
        blocks.append((block_name, "\n".join(block_lines)))
    return blocks


def has_exact_wipe(block, pointer, byte_count):
    return any(
        wipe_pointer(line) == pointer and has_byte_count(line, byte_count)
        for line in wipe_lines(block)
    )


def conditional_successors(block):
    branch = re.search(
        r'br i1 [^\n]*, label %"?([-.\w]+)"?, '
        r'label %"?([-.\w]+)"?',
        block,
    )
    if not branch:
        return None
    return branch.group(1), branch.group(2)


def unconditional_successor(block):
    branch = re.search(
        r'br label %"?([-.\w]+)"?',
        block,
    )
    return branch.group(1) if branch else None


def all_return_paths_wipe_and_end_key_block(body):
    if not re.search(
        r"%keyBlock = alloca %T[^,\n]*SIMD64[^,\n]*, align ",
        body,
    ):
        return False

    blocks = basic_blocks(body)
    if not blocks:
        return False
    blocks_by_name = dict(blocks)
    pending = [(blocks[0][0], False, False)]
    visited = set()

    while pending:
        block_name, already_wiped, already_ended = pending.pop()
        state = (block_name, already_wiped, already_ended)
        if state in visited:
            continue
        visited.add(state)

        block = blocks_by_name.get(block_name)
        if block is None:
            return False

        wipe_indexes = [
            block.find(line)
            for line in wipe_lines(block)
            if wipe_pointer(line) == "%keyBlock"
            and has_byte_count(line, 64)
        ]
        lifetime_end = re.search(
            r"llvm\.lifetime\.end[^\n]*ptr (?:nonnull )?%keyBlock\)",
            block,
        )
        wiped = already_wiped or bool(wipe_indexes)
        ended = already_ended
        if lifetime_end:
            if not already_wiped and (
                not wipe_indexes
                or min(wipe_indexes) >= lifetime_end.start()
            ):
                return False
            ended = True

        if re.search(r"^\s*ret\b", block, re.MULTILINE):
            if not wiped or not ended:
                return False
            continue
        if re.search(r"^\s*unreachable\b", block, re.MULTILINE):
            continue

        successors = conditional_successors(block)
        if successors is None:
            successor = unconditional_successor(block)
            if successor is None:
                return False
            successors = (successor,)
        for successor in successors:
            pending.append((successor, wiped, ended))

    return True


def has_normalization_context_cleanup(body):
    owner_match = re.search(
        r"(%[-.\w]*normalizationContext[-.\w]*) = alloca "
        r"%T[^,\n]*SHA256Context[^,\n]*, align ",
        body,
    )
    if not owner_match:
        return False
    owner = owner_match.group(1)

    pending_pointers = re.findall(
        r"(%[-.\w]+) = getelementptr[^\n]*ptr "
        + re.escape(owner)
        + r", i(?:32|64) 32",
        body,
    )
    for pending_pointer in pending_pointers:
        cleanup_blocks = []
        for block_name, block in basic_blocks(body):
            if not has_exact_wipe(block, owner, 32):
                continue
            if not has_exact_wipe(block, pending_pointer, 64):
                continue

            state_wipe_index = min(
                block.find(line)
                for line in wipe_lines(block)
                if wipe_pointer(line) == owner and has_byte_count(line, 32)
            )
            pending_wipe_index = min(
                block.find(line)
                for line in wipe_lines(block)
                if wipe_pointer(line) == pending_pointer
                and has_byte_count(line, 64)
            )
            lifetime_end = re.search(
                r"llvm\.lifetime\.end[^\n]*ptr (?:nonnull )?"
                + re.escape(owner)
                + r"\)",
                block,
            )
            if not lifetime_end:
                continue
            if max(state_wipe_index, pending_wipe_index) >= lifetime_end.start():
                continue
            cleanup_blocks.append((block_name, block))

        cleanup_by_name = dict(cleanup_blocks)
        update_failure_cleanup_verified = False
        finalize_cleanup_verified = False

        for block_name, block in basic_blocks(body):
            successors = conditional_successors(block)
            if not successors:
                continue

            error_successors = [
                successor
                for successor in successors
                if "error" in successor
            ]
            non_error_successors = [
                successor
                for successor in successors
                if "error" not in successor
            ]
            if len(error_successors) != 1 or len(non_error_successors) != 1:
                continue

            if (
                "SHA256ContextV6update" in block
                and owner in block
                and error_successors[0] in cleanup_by_name
            ):
                update_failure_cleanup_verified = True

            if "SHA256ContextV15finalizeInPlace" not in block:
                continue
            if owner not in block:
                continue

            merged_cleanup = block_name in cleanup_by_name
            split_cleanup = all(
                successor in cleanup_by_name
                for successor in successors
            )
            if merged_cleanup or split_cleanup:
                finalize_cleanup_verified = True

        if update_failure_cleanup_verified and finalize_cleanup_verified:
            return True
    return False


def outlined_wipe_helper_is_verified(defer_body):
    if any(
        operation in defer_body
        for operation in key_setup_heap_operations
    ):
        return False

    zero_comparison = re.search(
        r"(%[-.\w]+) = icmp eq i(32|64) %1, 0",
        defer_body,
    )
    if not zero_comparison:
        return False
    width = zero_comparison.group(2)

    difference = re.search(
        r"(%[-.\w]+) = sub i"
        + width
        + r" %2, %1",
        defer_body,
    )
    if not difference:
        return False

    selected_count = re.search(
        r"(%[-.\w]+) = select i1 "
        + re.escape(zero_comparison.group(1))
        + r", i"
        + width
        + r" 0, i"
        + width
        + r" "
        + re.escape(difference.group(1)),
        defer_body,
    )
    if not selected_count:
        return False

    return re.search(
        r"SecureWipeO5erase[^\n]*"
        r"\(ptr (?:nonnull )?%0, i"
        + width
        + r" "
        + re.escape(selected_count.group(1))
        + r"\)",
        defer_body,
    ) is not None


def outlined_key_block_cleanup_is_verified(body):
    if not re.search(
        r"%keyBlock = alloca %T[^,\n]*SIMD64[^,\n]*, align ",
        body,
    ):
        return False

    key_block_start = re.search(
        r"(%[-.\w]+) = ptrtoint ptr %keyBlock to i(?:32|64)",
        body,
    )
    key_block_end_pointer = re.search(
        r"(%[-.\w]+) = getelementptr[^\n]*"
        r"ptr %keyBlock, i(?:32|64) 64",
        body,
    )
    if not key_block_start or not key_block_end_pointer:
        return False

    key_block_end = re.search(
        r"(%[-.\w]+) = ptrtoint ptr "
        + re.escape(key_block_end_pointer.group(1))
        + r" to i(?:32|64)",
        body,
    )
    if not key_block_end:
        return False

    closure_calls = re.findall(
        r'call swiftcc void @"([^"]*'
        r'HMACSHA256CoreO23initializeFreshContexts[^"]*EfU_)"'
        r'\([^\n]*i(?:32|64) '
        + re.escape(key_block_start.group(1))
        + r", i(?:32|64) "
        + re.escape(key_block_end.group(1))
        + r",",
        body,
    )
    for closure_symbol in closure_calls:
        for closure_body in function_bodies(closure_symbol):
            if any(
                operation in closure_body
                for operation in key_setup_heap_operations
            ):
                continue
            if not has_normalization_context_cleanup(closure_body):
                continue

            key_pointer = re.search(
                r"(%[-.\w]+) = inttoptr i(?:32|64) %1 to ptr",
                closure_body,
            )
            if not key_pointer:
                continue

            defer_calls = []
            defer_call_pattern = re.compile(
                r'call swiftcc void @"([^"]*'
                r'HMACSHA256CoreO23initializeFreshContexts'
                r'[^"]*\$defer[^"]*)"\('
                r"ptr (?:nonnull )?"
                + re.escape(key_pointer.group(1))
                + r", i(?:32|64) %1, i(?:32|64) %2\)"
            )
            for block_name, block in basic_blocks(closure_body):
                for defer_call in defer_call_pattern.finditer(block):
                    defer_calls.append(
                        (defer_call.group(1), block_name)
                    )

            for defer_symbol in {call[0] for call in defer_calls}:
                call_blocks = {
                    block_name
                    for symbol, block_name in defer_calls
                    if symbol == defer_symbol
                }
                if (
                    len(call_blocks) < 2
                    or not any("error" in name for name in call_blocks)
                    or not any("error" not in name for name in call_blocks)
                ):
                    continue
                for defer_body in function_bodies(defer_symbol):
                    if outlined_wipe_helper_is_verified(defer_body):
                        return True
    return False


key_setup_verified = False
for body in function_bodies(
    "HMACSHA256CoreO23initializeFreshContexts"
):
    if any(operation in body for operation in key_setup_heap_operations):
        continue

    if (
        all_return_paths_wipe_and_end_key_block(body)
        and has_normalization_context_cleanup(body)
    ) or outlined_key_block_cleanup_is_verified(body):
        key_setup_verified = True
        break
if not key_setup_verified:
    raise RuntimeError(
        f"{label}: allocation-free HMAC key setup cleanup is missing"
    )


inner_digest_verified = False
for body in function_bodies("finalizeAuthenticationCode"):
    digest_wipes = [
        line
        for line in wipe_lines(body)
        if "%innerDigest" in line and has_byte_count(line, 32)
    ]
    if len(digest_wipes) >= 2:
        inner_digest_verified = True
        break
if not inner_digest_verified:
    raise RuntimeError(
        f"{label}: HMAC inner digest cleanup is missing on an exit path"
    )


verification_tag_verified = False
for body in function_bodies("isValidAuthenticationCode"):
    tag_wipes = [
        line
        for line in wipe_lines(body)
        if "%calculatedCode" in line and has_byte_count(line, 32)
    ]
    if len(tag_wipes) >= 2 and "ConstantTimeO5equal" in body:
        verification_tag_verified = True
        break
if not verification_tag_verified:
    raise RuntimeError(
        f"{label}: HMAC verification tag cleanup or constant-time call is missing"
    )


heap_operations = (
    "swift_allocObject",
    "swift_retain",
    "swift_release",
    "malloc(",
    "call void @free",
)


def require_scoped_context_wipes(body, context_names, operation):
    wipes = wipe_lines(body)
    for context_name in context_names:
        state_wipes = [
            line
            for line in wipes
            if wipe_pointer(line) == context_name
            and has_byte_count(line, 32)
        ]
        pending_wipes = [
            line
            for line in wipes
            if wipe_pointer(line)
            and re.search(
                rf"(?<![A-Za-z0-9])"
                rf"{re.escape(context_name.removeprefix('%'))}"
                rf"(?![A-Za-z0-9])",
                wipe_pointer(line),
            )
            and has_byte_count(line, 64)
        ]
        if len(state_wipes) < 2 or len(pending_wipes) < 2:
            raise RuntimeError(
                f"{label}: {operation} does not wipe {context_name} "
                "on success and failure"
            )


one_shot_verified = False
for body in function_bodies("HMACSHA256O12authenticate_5using4into"):
    if any(operation in body for operation in heap_operations):
        continue
    if body.count("HMACSHA256CoreO23initializeFreshContexts") != 1:
        continue
    contexts = sorted(
        set(
            re.findall(
                r"(%(?:inner|outer)Context[-.\w]*) = alloca "
                r"%T14SSLCrypto13SHA256ContextV",
                body,
            )
        )
    )
    if len(contexts) != 4:
        continue
    require_scoped_context_wipes(body, contexts, "one-shot HMAC")
    one_shot_digest_wipes = [
        line
        for line in wipe_lines(body)
        if wipe_pointer(line) == "%innerDigest"
        and has_byte_count(line, 32)
    ]
    if (
        len(one_shot_digest_wipes) < 2
        and "HMACSHA256CoreO26finalizeAuthenticationCode" not in body
    ):
        continue
    one_shot_verified = True
    break
if not one_shot_verified:
    raise RuntimeError(
        f"{label}: one-shot HMAC is not allocation-free with scoped cleanup"
    )


def assigned_values(body):
    assignments = {}
    for line in body.splitlines():
        match = re.match(r"\s*(%[-.\w]+) = (.*)", line)
        if match:
            assignments[match.group(1)] = match.group(2)
    return assignments


def transitive_values(assignments, roots):
    derived = set(roots)
    changed = True
    while changed:
        changed = False
        for result, expression in assignments.items():
            if result in derived:
                continue
            if any(
                re.search(
                    rf"(?<![-.\w]){re.escape(value)}(?![-.\w])",
                    expression,
                )
                for value in derived
            ):
                derived.add(result)
                changed = True
    return derived


def block_labels_for_matching_lines(body, predicate):
    labels = set()
    current_label = "entry"
    for line in body.splitlines():
        label_match = re.match(r'^("[^"]+"|[-.\w]+):', line)
        if label_match:
            current_label = label_match.group(1)
        if predicate(line):
            labels.add(current_label)
    return labels


hkdf_verified = False
for body in function_bodies("HKDFSHA256O6expand"):
    if any(operation in body for operation in heap_operations):
        continue
    if body.count("HMACSHA256CoreO23initializeFreshContexts") != 1:
        continue

    context_names = sorted(
        set(
            re.findall(
                r"(%(?:inner|outer)Context[-.\w]*) = alloca "
                r"%T14SSLCrypto13SHA256ContextV",
                body,
            )
        )
    )
    if len(context_names) != 4:
        continue
    require_scoped_context_wipes(body, context_names, "HKDF expand")

    digest_names = sorted(
        set(
            re.findall(
                r"(%innerDigest[-.\w]*) = alloca "
                r"%Ts6SIMD32Vys5UInt8VG",
                body,
            )
        )
    )
    if len(digest_names) != 2:
        continue
    if any(
        sum(
            1
            for line in wipe_lines(body)
            if wipe_pointer(line) == digest_name
            and has_byte_count(line, 32)
        )
        < 2
        for digest_name in digest_names
    ):
        continue

    if not re.search(
        r"%fullBlock = alloca %Ts6SIMD32Vys5UInt8VG",
        body,
    ):
        continue
    full_block_wipe_labels = block_labels_for_matching_lines(
        body,
        lambda line: (
            "SecureWipeO5erase" in line
            and wipe_pointer(line) == "%fullBlock"
            and has_byte_count(line, 32)
        ),
    )
    if len(full_block_wipe_labels) < 2:
        continue
    if re.search(r"\bret[^\n]*%fullBlock(?![-.\w])", body):
        continue
    if re.search(
        r"store ptr (?:nonnull )?%fullBlock(?![-.\w])",
        body,
    ):
        continue

    assignments = assigned_values(body)
    output_derived = transitive_values(assignments, {"%4"})
    full_block_derived = transitive_values(assignments, {"%fullBlock"})
    block_outputs = sorted(
        set(
            re.findall(
                r"(%blockOutput[-.\w]*) = alloca %Ts11MutableSpanV",
                body,
            )
        )
    )
    if len(block_outputs) != 2:
        continue

    output_pointer_by_span = {}
    for line in body.splitlines():
        match = re.search(
            r"store i(?:32|64) (%[-.\w]+), "
            r"ptr (?:nonnull )?(%blockOutput[-.\w]*)(?:,|$)",
            line,
        )
        if match:
            output_pointer_by_span[match.group(2)] = match.group(1)
    direct_spans = [
        span
        for span, pointer in output_pointer_by_span.items()
        if pointer in output_derived and pointer not in full_block_derived
    ]
    partial_spans = [
        span
        for span, pointer in output_pointer_by_span.items()
        if pointer in full_block_derived
    ]
    if len(direct_spans) != 1 or len(partial_spans) != 1:
        continue

    direct_span = direct_spans[0]
    partial_span = partial_spans[0]
    if not any(
        "finalizeInPlace" in line
        and re.search(
            rf"(?<![-.\w]){re.escape(direct_span)}(?![-.\w])",
            line,
        )
        for line in body.splitlines()
    ):
        continue
    if not any(
        "finalizeInPlace" in line
        and re.search(
            rf"(?<![-.\w]){re.escape(partial_span)}(?![-.\w])",
            line,
        )
        for line in body.splitlines()
    ):
        continue

    has_partial_source_load = any(
        re.search(r"load .*, ptr (%[-.\w]+)", line)
        and re.search(r"load .*, ptr (%[-.\w]+)", line).group(1)
        in full_block_derived
        for line in body.splitlines()
    )
    has_caller_output_store = any(
        re.search(r"store .*, ptr (%[-.\w]+)", line)
        and re.search(r"store .*, ptr (%[-.\w]+)", line).group(1)
        in output_derived
        for line in body.splitlines()
    )
    has_bounded_partial_copy = False
    for line in body.splitlines():
        if "llvm.memcpy" not in line and "llvm.memmove" not in line:
            continue
        pointers = re.findall(
            r"ptr(?: [^,%)]*)? (%[-.\w]+)",
            line,
        )
        if (
            len(pointers) >= 2
            and pointers[0] in output_derived
            and pointers[1] in full_block_derived
            and re.search(r"i(?:32|64) %[-.\w]+, i1 false", line)
        ):
            has_bounded_partial_copy = True
            break
    if not (
        (has_partial_source_load and has_caller_output_store)
        or has_bounded_partial_copy
    ):
        continue

    hkdf_verified = True
    break
if not hkdf_verified:
    raise RuntimeError(
        f"{label}: HKDF direct output, allocation, or cleanup contract failed"
    )

print(
    f"{label}: HMAC/HKDF allocation-free scoped cleanup and "
    "direct-output code generation verified"
)
PYTHON
}

compile_crypto_configuration() {
    label="$1"
    file_prefix="$2"
    optimization="$3"
    shift 3

    module_directory="$artifact_directory/$file_prefix-modules"
    crypto_ir="$artifact_directory/$file_prefix-crypto-wmo.ll"
    core_ir="$artifact_directory/$file_prefix-core-wmo.ll"
    mkdir -p "$module_directory"

    # shellcheck disable=SC2086
    "$swiftc_path" $core_sources $optimization -wmo -emit-module -emit-ir \
        $core_common_flags "$@" \
        -o "$core_ir" \
        -emit-module-path "$module_directory/SSLCore.swiftmodule"

    # shellcheck disable=SC2086
    "$swiftc_path" $crypto_sources $optimization -wmo -emit-ir \
        $crypto_common_flags -I "$module_directory" "$@" \
        -o "$crypto_ir"

    validate_crypto_ir "$label" "$crypto_ir" "$core_ir"
}

compile_configuration() {
    label="$1"
    file_prefix="$2"
    optimization="$3"
    shift 3

    whole_module_ir="$artifact_directory/$file_prefix-wmo.ll"
    secret_bytes_ir="$artifact_directory/$file_prefix-secret.ll"
    secure_wipe_ir="$artifact_directory/$file_prefix-wipe.ll"

    # shellcheck disable=SC2086
    "$swiftc_path" $core_sources Validation/SecureWipe/SecureWipeProductionProbe.swift \
        $optimization -wmo -emit-ir $core_common_flags "$@" -o "$whole_module_ir"

    secret_other_sources="$(find Sources/SSLCore -name '*.swift' -type f ! -name 'SecretBytes.swift' | sort)"
    # shellcheck disable=SC2086
    "$swiftc_path" -frontend -emit-ir $secret_other_sources \
        -primary-file Sources/SSLCore/SecretBytes.swift \
        $optimization $core_common_flags "$@" -o "$secret_bytes_ir"

    wipe_other_sources="$(find Sources/SSLCore -name '*.swift' -type f ! -name 'SecureWipe.swift' | sort)"
    # shellcheck disable=SC2086
    "$swiftc_path" -frontend -emit-ir $wipe_other_sources \
        -primary-file Sources/SSLCore/SecureWipe.swift \
        $optimization $core_common_flags "$@" -o "$secure_wipe_ir"

    validate_ir "$label" "$whole_module_ir" "$secret_bytes_ir" "$secure_wipe_ir" standard
    compile_crypto_configuration \
        "$label" \
        "$file_prefix" \
        "$optimization" \
        "$@"
}

compile_embedded_configuration() {
    label="$1"
    file_prefix="$2"
    optimization="$3"

    whole_module_ir="$artifact_directory/$file_prefix-wmo.ll"
    # shellcheck disable=SC2086
    "$swiftc_path" $core_sources Validation/SecureWipe/SecureWipeProductionProbe.swift \
        $optimization -wmo -emit-ir $core_common_flags \
        -target wasm32-unknown-wasip1 \
        -sdk "$embedded_sdk_root" \
        -resource-dir "$embedded_resources" \
        -enable-experimental-feature Embedded \
        -o "$whole_module_ir"

    validate_ir "$label" "$whole_module_ir" "$whole_module_ir" "$whole_module_ir" embedded
    compile_crypto_configuration \
        "$label" \
        "$file_prefix" \
        "$optimization" \
        -target wasm32-unknown-wasip1 \
        -sdk "$embedded_sdk_root" \
        -resource-dir "$embedded_resources" \
        -enable-experimental-feature Embedded
}

python3 Validation/SecureWipe/verify_crypto_ir.py --self-test

for optimization in $optimizations; do
    suffix="$(printf '%s' "$optimization" | tr -d '-')"
    if [ "$codegen_target" = all ] || [ "$codegen_target" = native ]; then
        compile_configuration "Native $optimization" "native-$suffix" "$optimization"
    fi
    if [ "$codegen_target" = all ] || [ "$codegen_target" = wasi ]; then
        compile_configuration \
            "WASI $optimization" \
            "wasi-$suffix" \
            "$optimization" \
            -target wasm32-unknown-wasip1 \
            -sdk "$wasi_sdk_root" \
            -resource-dir "$wasi_resources"
    fi
    if [ "$codegen_target" = all ] || [ "$codegen_target" = embedded-wasi ]; then
        compile_embedded_configuration \
            "Embedded WASI $optimization" \
            "embedded-wasi-$suffix" \
            "$optimization"
    fi
done

ir_hashes="$evidence_directory/ir-sha256.txt"
for ir_file in "$artifact_directory"/*.ll; do
    if [ -f "$ir_file" ]; then
        shasum -a 256 "$ir_file" >>"$ir_hashes"
    fi
done
printf '%s\n' \
    "toolchain=$toolchain_identifier" \
    "compiler_commit=$expected_compiler_commit" \
    "wasi_sdk=$wasi_sdk_identifier" \
    "embedded_sdk=$embedded_sdk_identifier" \
    "target=${SWIFT_SSL_CODEGEN_TARGET:-all}" \
    "optimization=${SWIFT_SSL_CODEGEN_OPTIMIZATION:-all}" \
    >"$evidence_directory/manifest.txt"
echo "Code-generation validation passed; evidence: $evidence_directory"
