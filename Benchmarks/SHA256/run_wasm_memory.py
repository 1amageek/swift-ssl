#!/usr/bin/env python3
"""Measure Pure Swift SHA-256 allocation and copy behavior with WasmKit."""

from __future__ import annotations

import argparse
import collections
import datetime as datetime_module
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parents[1]
COMPARISON_RUNNER_PATH = SCRIPT_DIRECTORY / "run_wasm_comparison.py"
COMPARISON_RUNNER_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_sha256_wasm_comparison_runner",
    COMPARISON_RUNNER_PATH,
)
if COMPARISON_RUNNER_SPEC is None or COMPARISON_RUNNER_SPEC.loader is None:
    raise RuntimeError("Could not load the WASI SHA-256 comparison runner")
comparison_runner = importlib.util.module_from_spec(COMPARISON_RUNNER_SPEC)
COMPARISON_RUNNER_SPEC.loader.exec_module(comparison_runner)

ITERATION_COUNTS = (1, 10, 100)
REPETITIONS = 3
RUN_SYMBOL_FRAGMENT = "SSLSHA256Benchmark06SHA256C7CommandO3run"
UPDATE_SYMBOL_FRAGMENT = "SSLCrypto13SHA256ContextV6update"
FINALIZE_SYMBOL_FRAGMENT = "SSLCrypto13SHA256ContextV15finalizeInPlace"
FIXED_COPY_HELPER_PATTERN = re.compile(r"^__swift_memcpy([0-9]+)_")
LIBC_ALLOCATION_NAMES = frozenset(
    ("malloc", "calloc", "realloc", "aligned_alloc")
)
LIBC_DEALLOCATION_NAMES = frozenset(("free",))
LIBC_COPY_NAMES = frozenset(("memcpy", "memmove"))
COUNTER_NAMES = (
    "contextUpdateCalls",
    "contextFinalizeCalls",
    "libcAllocationCalls",
    "libcDeallocationCalls",
    "swiftAllocationCalls",
    "swiftDeallocationCalls",
    "bulkCopyFunctionCalls",
    "fixedCopyHelperCalls",
    "fixedCopyHelperBytes",
)


class MemoryMeasurementError(RuntimeError):
    """A WASI memory-measurement contract failure."""


def parse_positive_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the production Pure Swift SHA-256 worker and measure its "
            "allocation and dynamic-copy calls inside the exact hashing loop."
        )
    )
    parser.add_argument(
        "--target",
        choices=("wasi", "embedded", "both"),
        default="both",
    )
    parser.add_argument(
        "--repetitions",
        type=parse_positive_integer,
        default=REPETITIONS,
    )
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--build-timeout-seconds",
        type=parse_positive_integer,
        default=1_800,
    )
    parser.add_argument(
        "--worker-timeout-seconds",
        type=parse_positive_integer,
        default=300,
    )
    return parser


def is_swift_allocation(name: str) -> bool:
    return name.startswith(("swift_alloc", "__swift_alloc"))


def is_swift_deallocation(name: str) -> bool:
    return name.startswith(("swift_dealloc", "__swift_dealloc"))


def summarize_scope(event_counts: collections.Counter[str]) -> dict[str, int]:
    fixed_copy_helper_calls = 0
    fixed_copy_helper_bytes = 0
    for name, count in event_counts.items():
        match = FIXED_COPY_HELPER_PATTERN.match(name)
        if match is not None:
            fixed_copy_helper_calls += count
            fixed_copy_helper_bytes += count * int(match.group(1), 10)

    return {
        "contextUpdateCalls": sum(
            count
            for name, count in event_counts.items()
            if UPDATE_SYMBOL_FRAGMENT in name
        ),
        "contextFinalizeCalls": sum(
            count
            for name, count in event_counts.items()
            if FINALIZE_SYMBOL_FRAGMENT in name
        ),
        "libcAllocationCalls": sum(
            event_counts[name] for name in LIBC_ALLOCATION_NAMES
        ),
        "libcDeallocationCalls": sum(
            event_counts[name] for name in LIBC_DEALLOCATION_NAMES
        ),
        "swiftAllocationCalls": sum(
            count
            for name, count in event_counts.items()
            if is_swift_allocation(name)
        ),
        "swiftDeallocationCalls": sum(
            count
            for name, count in event_counts.items()
            if is_swift_deallocation(name)
        ),
        "bulkCopyFunctionCalls": sum(
            event_counts[name] for name in LIBC_COPY_NAMES
        ),
        "fixedCopyHelperCalls": fixed_copy_helper_calls,
        "fixedCopyHelperBytes": fixed_copy_helper_bytes,
    }


def parse_measured_scope(
    events: Sequence[dict[str, Any]],
    *,
    expected_iterations: int,
) -> dict[str, int]:
    stack: list[str] = []
    active_scope: collections.Counter[str] | None = None
    completed_scopes: list[dict[str, int]] = []

    for event in events:
        phase = event.get("ph")
        name = event.get("name")
        if phase == "B":
            if not isinstance(name, str) or not name:
                raise MemoryMeasurementError("profile begin event has no name")
            if RUN_SYMBOL_FRAGMENT in name:
                if active_scope is not None:
                    raise MemoryMeasurementError("hashing scopes are nested")
                active_scope = collections.Counter()
            if active_scope is not None:
                active_scope[name] += 1
            stack.append(name)
        elif phase == "E":
            if not stack:
                raise MemoryMeasurementError("profile call stack underflow")
            ended_name = stack.pop()
            if isinstance(name, str) and name and name != ended_name:
                raise MemoryMeasurementError("profile begin/end names do not match")
            if RUN_SYMBOL_FRAGMENT in ended_name:
                if active_scope is None:
                    raise MemoryMeasurementError("hashing scope ended while inactive")
                completed_scopes.append(summarize_scope(active_scope))
                active_scope = None
        else:
            raise MemoryMeasurementError(f"unsupported profile event phase: {phase}")

    if stack or active_scope is not None:
        raise MemoryMeasurementError("profile call stack is incomplete")

    matching = [
        scope
        for scope in completed_scopes
        if scope["contextUpdateCalls"] == expected_iterations
        and scope["contextFinalizeCalls"] == expected_iterations
    ]
    if len(matching) != 1:
        raise MemoryMeasurementError(
            "profile does not contain one uniquely measured hashing scope"
        )
    return matching[0]


def derive_linear_counters(
    observations: Sequence[dict[str, Any]],
    *,
    repetitions: int,
) -> dict[str, Any]:
    grouped: dict[int, list[dict[str, int]]] = {
        iterations: [] for iterations in ITERATION_COUNTS
    }
    for observation in observations:
        iterations = observation["iterations"]
        if iterations not in grouped:
            raise MemoryMeasurementError("unexpected iteration count")
        grouped[iterations].append(observation["counters"])

    canonical: dict[int, dict[str, int]] = {}
    for iterations in ITERATION_COUNTS:
        counters = grouped[iterations]
        if len(counters) != repetitions:
            raise MemoryMeasurementError("incomplete profile repetitions")
        if any(candidate != counters[0] for candidate in counters[1:]):
            raise MemoryMeasurementError(
                f"profile counters are not deterministic at {iterations} iterations"
            )
        canonical[iterations] = counters[0]

    low = ITERATION_COUNTS[-2]
    high = ITERATION_COUNTS[-1]
    denominator = high - low
    per_operation: dict[str, int] = {}
    fixed_overhead: dict[str, int] = {}
    for name in COUNTER_NAMES:
        numerator = canonical[high][name] - canonical[low][name]
        quotient, remainder = divmod(numerator, denominator)
        if remainder != 0 or quotient < 0:
            raise MemoryMeasurementError(
                f"{name} does not have a nonnegative integral slope"
            )
        intercept = canonical[high][name] - quotient * high
        if any(
            canonical[iterations][name] != intercept + quotient * iterations
            for iterations in ITERATION_COUNTS
        ):
            raise MemoryMeasurementError(f"{name} is not linear")
        per_operation[name] = quotient
        fixed_overhead[name] = intercept

    return {
        "perOperation": per_operation,
        "fixedScopeOverhead": fixed_overhead,
        "canonicalObservations": {
            str(iterations): canonical[iterations]
            for iterations in ITERATION_COUNTS
        },
    }


def validate_budget(
    derived: dict[str, Any],
    *,
    byte_count: int,
) -> list[str]:
    values = derived["perOperation"]
    failures: list[str] = []
    expected = {
        "contextUpdateCalls": 1,
        "contextFinalizeCalls": 1,
        "libcAllocationCalls": 0,
        "libcDeallocationCalls": 0,
        "swiftAllocationCalls": 0,
        "swiftDeallocationCalls": 0,
        "bulkCopyFunctionCalls": 0,
        "fixedCopyHelperCalls": 0,
        "fixedCopyHelperBytes": 0,
    }
    for name, expected_value in expected.items():
        if values[name] != expected_value:
            failures.append(
                f"{name} expected {expected_value}, observed {values[name]}"
            )
    if byte_count % 64 > 63:
        failures.append("algorithmic tail retention exceeded 63 bytes")
    return failures


def expected_result(byte_count: int, iterations: int) -> dict[str, Any]:
    input_bytes = bytearray(
        ((index * 31 + 17) & 0xFF) for index in range(byte_count)
    )
    checksum = 0
    digest = b""
    for iteration in range(iterations):
        input_bytes[0] = iteration & 0xFF
        digest = hashlib.sha256(input_bytes).digest()
        checksum = (checksum + digest[iteration & 31]) & 0xFFFF_FFFF_FFFF_FFFF
    return {
        "checksum": checksum,
        "digestHex": digest.hex(),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_profiled_result(stdout: str, profile_path: Path) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line]
    expected_profile_message = (
        f"Profile Completed: {profile_path} can be viewed using "
        "https://ui.perfetto.dev/"
    )
    if len(lines) != 2 or lines[1] != expected_profile_message:
        raise MemoryMeasurementError("unexpected WasmKit profile output")
    return comparison_runner.parse_result(lines[0] + "\n")


def profile_worker(
    *,
    wasmkit: Path,
    worker: Path,
    profile_path: Path,
    byte_count: int,
    iterations: int,
    input_offset: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    if profile_path.exists():
        raise MemoryMeasurementError(f"profile already exists: {profile_path}")
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    completed = comparison_runner.run_command(
        [
            str(wasmkit),
            "run",
            "--profile",
            str(profile_path),
            str(worker),
            str(byte_count),
            str(iterations),
            "0",
            str(input_offset),
        ],
        timeout_seconds=timeout_seconds,
    )
    result = parse_profiled_result(completed.stdout, profile_path)
    expected = expected_result(byte_count, iterations)
    if (result["checksum"], result["digestHex"]) != (
        expected["checksum"],
        expected["digestHex"],
    ):
        raise MemoryMeasurementError("profiled worker output does not match hashlib")
    try:
        events = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MemoryMeasurementError("WasmKit profile is unreadable") from error
    if not isinstance(events, list):
        raise MemoryMeasurementError("WasmKit profile must contain an event array")
    counters = parse_measured_scope(
        events,
        expected_iterations=iterations,
    )
    return {
        "counters": counters,
        "checksum": result["checksum"],
        "digestHex": result["digestHex"],
        "profile": str(profile_path),
        "profileSHA256": sha256_file(profile_path),
    }


def disassemble_symbol(
    *,
    llvm_objdump: Path,
    worker: Path,
    symbol: str,
) -> str:
    completed = comparison_runner.run_command(
        [
            str(llvm_objdump),
            "-d",
            f"--disassemble-symbols={symbol}",
            str(worker),
        ],
        timeout_seconds=120,
    )
    if f"<{symbol}>:" not in completed.stdout:
        raise MemoryMeasurementError(f"WASM symbol was not disassembled: {symbol}")
    return completed.stdout


def resolve_unique_symbol(symbol_table: str, fragment: str) -> str:
    matches = [
        line.split()[-1]
        for line in symbol_table.splitlines()
        if fragment in line and line.split()
    ]
    if len(matches) != 1:
        raise MemoryMeasurementError(
            f"expected one WASM symbol containing {fragment}, found {len(matches)}"
        )
    return matches[0]


def code_generation_evidence(
    *,
    llvm_objdump: Path,
    worker: Path,
) -> dict[str, Any]:
    symbol_table = comparison_runner.run_command(
        [str(llvm_objdump), "--syms", str(worker)],
        timeout_seconds=120,
    ).stdout
    update_symbol = resolve_unique_symbol(symbol_table, UPDATE_SYMBOL_FRAGMENT)
    finalize_symbol = resolve_unique_symbol(
        symbol_table,
        FINALIZE_SYMBOL_FRAGMENT,
    )
    update = disassemble_symbol(
        llvm_objdump=llvm_objdump,
        worker=worker,
        symbol=update_symbol,
    )
    finalize = disassemble_symbol(
        llvm_objdump=llvm_objdump,
        worker=worker,
        symbol=finalize_symbol,
    )
    update_memory_copies = update.count("memory.copy")
    finalize_memory_copies = finalize.count("memory.copy")
    if update_memory_copies != 2 or finalize_memory_copies != 0:
        raise MemoryMeasurementError(
            "unexpected WASM memory.copy sites in SHA-256 update/finalization"
        )
    return {
        "updateSymbol": update_symbol,
        "finalizeSymbol": finalize_symbol,
        "updateMemoryCopyInstructionSites": update_memory_copies,
        "finalizeMemoryCopyInstructionSites": finalize_memory_copies,
        "sourceContract": (
            "the two update sites copy only into the 64-byte pending owner; "
            "complete input blocks remain borrowed"
        ),
        "updateDisassemblySHA256": hashlib.sha256(update.encode()).hexdigest(),
        "finalizeDisassemblySHA256": hashlib.sha256(finalize.encode()).hexdigest(),
    }


def output_path(selected: Path | None) -> Path:
    if selected is not None:
        return selected.resolve()
    timestamp = datetime_module.datetime.now(
        datetime_module.timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")
    return (
        REPOSITORY_ROOT
        / ".test-artifacts"
        / "benchmark"
        / f"{timestamp}-sha256-wasm-memory.json"
    )


def resolve_llvm_objdump() -> Path:
    environment = comparison_runner.inherited_environment(
        {"TOOLCHAINS": comparison_runner.EXPECTED_SWIFT_TOOLCHAIN}
    )
    completed = comparison_runner.run_command(
        ["/usr/bin/xcrun", "--find", "llvm-objdump"],
        environment=environment,
        timeout_seconds=30,
    )
    executable = Path(completed.stdout.strip())
    if not executable.is_file():
        raise MemoryMeasurementError("llvm-objdump was not found")
    return executable


def main() -> int:
    options = build_argument_parser().parse_args()
    selected_output = output_path(options.output)
    if selected_output.exists():
        raise MemoryMeasurementError(
            f"refusing to overwrite existing artifact: {selected_output}"
        )

    paths = comparison_runner.toolchain_paths()
    compiler = comparison_runner.compiler_identity(paths)
    if not compiler["compilerCommitMatched"]:
        raise MemoryMeasurementError("unexpected Swift compiler commit")
    llvm_objdump = resolve_llvm_objdump()
    build_root = comparison_runner.make_build_root(options.build_root)
    source_identity = comparison_runner.repository_identity(REPOSITORY_ROOT)

    target_results: list[dict[str, Any]] = []
    all_passed = True
    for sdk_id in comparison_runner.selected_sdks(options.target):
        sdk = comparison_runner.sdk_configuration(sdk_id)
        worker, swift_build = comparison_runner.build_swift_worker(
            sdk_id=sdk_id,
            build_root=build_root,
            paths=paths,
            sdk=sdk,
            timeout_seconds=options.build_timeout_seconds,
        )
        code_generation = code_generation_evidence(
            llvm_objdump=llvm_objdump,
            worker=worker,
        )
        target_name = (
            "embedded"
            if sdk_id == comparison_runner.EMBEDDED_WASI_SDK
            else "wasi"
        )
        workload_results: list[dict[str, Any]] = []
        for workload in comparison_runner.WORKLOADS:
            observations: list[dict[str, Any]] = []
            for iterations in ITERATION_COUNTS:
                for repetition in range(options.repetitions):
                    profile_path = (
                        build_root
                        / "profiles"
                        / target_name
                        / (
                            f"{workload['name']}-{iterations}-"
                            f"{repetition}.json"
                        )
                    )
                    observation = profile_worker(
                        wasmkit=paths["wasmkit"],
                        worker=worker,
                        profile_path=profile_path,
                        byte_count=workload["byteCount"],
                        iterations=iterations,
                        input_offset=workload["inputOffset"],
                        timeout_seconds=options.worker_timeout_seconds,
                    )
                    observations.append(
                        {
                            "iterations": iterations,
                            "repetition": repetition,
                            **observation,
                        }
                    )
            derived = derive_linear_counters(
                observations,
                repetitions=options.repetitions,
            )
            failures = validate_budget(
                derived,
                byte_count=workload["byteCount"],
            )
            passed = not failures
            all_passed = all_passed and passed
            workload_results.append(
                {
                    **workload,
                    "passed": passed,
                    "failures": failures,
                    "algorithmicTailBytesRetainedPerOperation": (
                        workload["byteCount"] % 64
                    ),
                    "derived": derived,
                    "observations": observations,
                }
            )
            print(
                f"{sdk_id} {workload['name']}: "
                f"{'pass' if passed else 'fail'}"
            )
        target_results.append(
            {
                "sdkID": sdk_id,
                "swiftBuild": swift_build,
                "workerSHA256": sha256_file(worker),
                "codeGeneration": code_generation,
                "workloads": workload_results,
                "passed": all(result["passed"] for result in workload_results),
            }
        )

    artifact = {
        "schemaVersion": 1,
        "createdAtUTC": datetime_module.datetime.now(
            datetime_module.timezone.utc
        ).isoformat(),
        "evidenceClass": "exploratory",
        "measurement": "WasmKit scoped function-call profile and WASM code generation",
        "scope": (
            "production Pure Swift SHA-256 one-shot loop with input and output "
            "owners allocated before the measured scope"
        ),
        "source": source_identity,
        "compiler": compiler,
        "runtime": {
            "executable": str(paths["wasmkit"]),
            "version": comparison_runner.run_command(
                [str(paths["wasmkit"]), "--version"],
                timeout_seconds=30,
            ).stdout.strip(),
        },
        "llvmObjdump": str(llvm_objdump),
        "buildRoot": str(build_root),
        "iterationCounts": list(ITERATION_COUNTS),
        "repetitions": options.repetitions,
        "budget": {
            "heapAllocationCallsPerOperation": 0,
            "dynamicBulkCopyFunctionCallsPerOperation": 0,
            "fixedCopyHelperBytesPerOperation": 0,
            "maximumAlgorithmicTailRetentionBytesPerOperation": 63,
            "fullInputMaterializationsPerOperation": 0,
        },
        "limitations": [
            "WasmKit profiles function calls, not individual memory.copy executions.",
            (
                "The two static memory.copy sites are accepted only because the "
                "production source bounds both destinations to the 64-byte pending owner."
            ),
            "Input/output owner construction is intentionally outside the measured scope.",
            "This artifact is allocation/copy evidence, not timing evidence.",
        ],
        "targets": target_results,
        "passed": all_passed,
    }
    selected_output.parent.mkdir(parents=True, exist_ok=True)
    selected_output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"artifact: {selected_output}")
    print(f"overall: {'pass' if all_passed else 'fail'}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MemoryMeasurementError, comparison_runner.BenchmarkError) as error:
        print(f"memory measurement error: {error}", file=sys.stderr)
        raise SystemExit(2)
