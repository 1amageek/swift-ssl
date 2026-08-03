#!/usr/bin/env python3
"""Build and compare Pure Swift and portable BoringSSL SHA-256 on WASI."""

from __future__ import annotations

import argparse
import datetime as datetime_module
import hashlib
import json
import math
import os
import random
import re
import secrets
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence


EXPECTED_BORINGSSL_COMMIT = "ae49d2681a56ca7b8609f6039a770fda2a8eb550"
EXPECTED_SWIFT_TOOLCHAIN = "org.swift.64202607231a"
EXPECTED_SWIFT_COMPILER_COMMIT = "ef761e567dc94ee"
WASI_SDK = "swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm"
EMBEDDED_WASI_SDK = (
    "swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded"
)
TARGET_TRIPLE = "wasm32-unknown-wasip1"
TARGET_SPEEDUP = 1.10
MINIMUM_FORMAL_SAMPLES = 30
MINIMUM_BOOTSTRAP_RESAMPLES = 1_000
MINIMUM_SAMPLE_NANOSECONDS = 250_000_000
MAXIMUM_CALIBRATION_ITERATIONS = 4_096
RESULT_PATTERN = re.compile(r"^RESULT,([0-9]+),([0-9]+),([0-9a-f]{64})$")
DIGEST_PATTERN = re.compile(r"^DIGEST,([0-9]+),([0-9a-f]{64})$")
CAPABILITY_PATTERN = re.compile(r"^CAPABILITY,boringssl_asm,([01])$")
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parents[1]
BORINGSSL_WORKER_SOURCE = (
    SCRIPT_DIRECTORY / "WASM" / "BoringSSLWorker.cpp"
)
VALIDATION_CASES = (
    (1, 0),
    (55, 0),
    (56, 0),
    (63, 0),
    (64, 0),
    (65, 0),
    (65, 1),
    (16_384, 0),
    (16_385, 0),
    (16_385, 1),
    (1_048_576, 0),
    (1_048_577, 0),
    (1_048_577, 1),
)
WORKLOADS = (
    {
        "name": "one-shot-aligned-1MiB",
        "byteCount": 1_048_576,
        "inputOffset": 0,
    },
    {
        "name": "one-shot-aligned-1MiB-plus-1",
        "byteCount": 1_048_577,
        "inputOffset": 0,
    },
    {
        "name": "one-shot-unaligned-1MiB-plus-1",
        "byteCount": 1_048_577,
        "inputOffset": 1,
    },
)


class BenchmarkError(RuntimeError):
    """A benchmark contract or execution failure."""


def utc_timestamp() -> str:
    return datetime_module.datetime.now(
        datetime_module.timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")


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
            "Build the production Pure Swift SHA-256 worker and a portable "
            "official BoringSSL worker, validate identical outputs, then "
            "collect paired WASI measurements."
        )
    )
    parser.add_argument(
        "--boringssl-source",
        required=True,
        type=Path,
        help="Clean checkout of the pinned official BoringSSL commit.",
    )
    parser.add_argument(
        "--target",
        choices=("wasi", "embedded", "both"),
        default="both",
        help="Swift execution target to measure (default: both).",
    )
    parser.add_argument(
        "--samples",
        type=parse_positive_integer,
        default=11,
        help="Paired samples per workload (default: 11).",
    )
    parser.add_argument(
        "--bootstrap-resamples",
        type=parse_positive_integer,
        default=10_000,
        help="Paired bootstrap resamples (default: 10000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0x535749465453534C,
        help="Randomization seed.",
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        help="Fresh build directory; it must not already exist.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="JSON artifact path under .test-artifacts by default.",
    )
    parser.add_argument(
        "--build-timeout-seconds",
        type=parse_positive_integer,
        default=1_800,
    )
    parser.add_argument(
        "--worker-timeout-seconds",
        type=parse_positive_integer,
        default=180,
    )
    parser.add_argument(
        "--formal",
        action="store_true",
        help=(
            "Require clean repositories, at least 30 pairs, and the exact "
            "compiler commit."
        ),
    )
    parser.add_argument(
        "--enforce-target",
        action="store_true",
        help="Exit unsuccessfully unless every confidence bound reaches 1.10x.",
    )
    return parser


def inherited_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("HOME", "LOGNAME", "TMPDIR", "USER")
        if name in os.environ
    }
    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
    )
    if overrides is not None:
        environment.update(overrides)
    return environment


def resolve_executable(candidates: Sequence[Path], label: str) -> Path:
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.absolute()
    raise BenchmarkError(f"{label} executable was not found")


def run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    start = time.monotonic_ns()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=environment if environment is not None else inherited_environment(),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise BenchmarkError(f"command failed to execute: {command[0]}") from error
    wall_nanoseconds = time.monotonic_ns() - start
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-4_000:]
        raise BenchmarkError(
            f"command exited {completed.returncode}: {' '.join(command)}\n{detail}"
        )
    completed.wall_nanoseconds = wall_nanoseconds  # type: ignore[attr-defined]
    return completed


def git_output(repository: Path, arguments: Sequence[str]) -> str:
    completed = run_command(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        timeout_seconds=30,
    )
    return completed.stdout.strip()


def repository_identity(repository: Path) -> dict[str, Any]:
    return {
        "path": str(repository.resolve()),
        "commit": git_output(repository, ("rev-parse", "HEAD")),
        "clean": not bool(
            git_output(
                repository,
                ("status", "--porcelain", "--untracked-files=all"),
            )
        ),
    }


def require_boringssl_source(source: Path) -> dict[str, Any]:
    resolved = source.resolve()
    identity = repository_identity(resolved)
    if identity["commit"] != EXPECTED_BORINGSSL_COMMIT:
        raise BenchmarkError(
            "BoringSSL commit mismatch: "
            f"expected {EXPECTED_BORINGSSL_COMMIT}, found {identity['commit']}"
        )
    if not identity["clean"]:
        raise BenchmarkError("BoringSSL checkout must be clean")
    return identity


def toolchain_paths() -> dict[str, Path]:
    environment = inherited_environment(
        {"TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN}
    )

    def xcrun_find(name: str) -> Path:
        completed = run_command(
            ["/usr/bin/xcrun", "--find", name],
            environment=environment,
            timeout_seconds=30,
        )
        executable = Path(completed.stdout.strip())
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise BenchmarkError(f"xcrun returned an invalid {name} executable")
        return executable

    return {
        "swift": xcrun_find("swift"),
        "clang": xcrun_find("clang"),
        "clang++": xcrun_find("clang++"),
        "llvm-ar": xcrun_find("llvm-ar"),
        "cmake": resolve_executable(
            (
                Path("/opt/homebrew/bin/cmake"),
                Path("/usr/local/bin/cmake"),
                Path("/usr/bin/cmake"),
            ),
            "CMake",
        ),
        "ninja": resolve_executable(
            (
                Path("/opt/homebrew/bin/ninja"),
                Path("/usr/local/bin/ninja"),
                Path("/usr/bin/ninja"),
            ),
            "Ninja",
        ),
        "wasmkit": xcrun_find("wasmkit"),
    }


def compiler_identity(paths: dict[str, Path]) -> dict[str, Any]:
    completed = run_command(
        [str(paths["swift"]), "--version"],
        timeout_seconds=30,
    )
    version = completed.stdout.strip()
    return {
        "toolchain": EXPECTED_SWIFT_TOOLCHAIN,
        "swiftExecutable": str(paths["swift"]),
        "clangExecutable": str(paths["clang"]),
        "version": version,
        "expectedCompilerCommit": EXPECTED_SWIFT_COMPILER_COMMIT,
        "compilerCommitMatched": EXPECTED_SWIFT_COMPILER_COMMIT in version,
    }


def sdk_configuration(sdk_id: str) -> dict[str, Path]:
    completed = run_command(
        [
            "/usr/bin/xcrun",
            "swift",
            "sdk",
            "configure",
            "--show-configuration",
            sdk_id,
        ],
        environment=inherited_environment(
            {"TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN}
        ),
        timeout_seconds=30,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value
    if "sdkRootPath" not in values:
        raise BenchmarkError(f"Swift SDK configuration is incomplete: {sdk_id}")
    sdk_root = Path(values["sdkRootPath"]).resolve()
    bundle_target_root = sdk_root.parent
    return {
        "sdkRoot": sdk_root,
        "bundleTargetRoot": bundle_target_root,
        "clangResourceDirectory": (
            bundle_target_root
            / "swift.xctoolchain/usr/lib/swift_static/clang"
        ),
        "unicodeDataTables": (
            bundle_target_root
            / (
                "swift.xctoolchain/usr/lib/swift/embedded/"
                f"{TARGET_TRIPLE}/libswiftUnicodeDataTables.a"
            )
        ),
    }


def make_build_root(path: Path | None) -> Path:
    selected = (
        path.resolve()
        if path is not None
        else (
            REPOSITORY_ROOT
            / ".build"
            / "sha256-wasm-benchmark"
            / f"{utc_timestamp()}-{secrets.token_hex(4)}"
        )
    )
    if selected.exists():
        raise BenchmarkError(f"build root already exists: {selected}")
    selected.mkdir(parents=True)
    return selected


def build_boringssl(
    *,
    source: Path,
    build_root: Path,
    paths: dict[str, Path],
    sdk: dict[str, Path],
    timeout_seconds: int,
) -> tuple[Path, dict[str, Any]]:
    build_directory = build_root / "boringssl"
    common_definitions = (
        "-DOPENSSL_NO_SOCK "
        "-DOPENSSL_NO_POSIX_IO "
        "-DOPENSSL_NO_FILESYSTEM "
        "-DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED"
    )
    configure_command = [
        str(paths["cmake"]),
        "-S",
        str(source),
        "-B",
        str(build_directory),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DOPENSSL_NO_ASM=1",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DCMAKE_SYSTEM_NAME=WASI",
        "-DCMAKE_SYSTEM_PROCESSOR=wasm32",
        f"-DCMAKE_C_COMPILER={paths['clang']}",
        f"-DCMAKE_CXX_COMPILER={paths['clang++']}",
        f"-DCMAKE_AR={paths['llvm-ar']}",
        f"-DCMAKE_MAKE_PROGRAM={paths['ninja']}",
        f"-DCMAKE_SYSROOT={sdk['sdkRoot']}",
        f"-DCMAKE_C_COMPILER_TARGET={TARGET_TRIPLE}",
        f"-DCMAKE_CXX_COMPILER_TARGET={TARGET_TRIPLE}",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
        f"-DCMAKE_C_FLAGS={common_definitions}",
        f"-DCMAKE_CXX_FLAGS={common_definitions}",
    ]
    run_command(
        configure_command,
        cwd=REPOSITORY_ROOT,
        timeout_seconds=timeout_seconds,
    )
    run_command(
        [
            str(paths["cmake"]),
            "--build",
            str(build_directory),
            "--target",
            "crypto",
            "-j",
            "4",
        ],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=timeout_seconds,
    )
    archive = build_directory / "libcrypto.a"
    compile_database = build_directory / "compile_commands.json"
    if not archive.is_file() or not compile_database.is_file():
        raise BenchmarkError("BoringSSL build did not produce audited artifacts")

    database = json.loads(compile_database.read_text(encoding="utf-8"))
    sha_entries = [
        entry
        for entry in database
        if str(entry.get("file", "")).endswith(
            (
                "/crypto/fipsmodule/bcm.cc",
                "/crypto/sha/sha256.cc",
            )
        )
    ]
    if len(sha_entries) != 2:
        raise BenchmarkError("BoringSSL SHA-256 compile entries are incomplete")
    for entry in sha_entries:
        command = entry.get("command", "")
        arguments = entry.get("arguments", [])
        flattened = command if command else " ".join(arguments)
        if "-O3" not in flattened or "OPENSSL_NO_ASM" not in flattened:
            raise BenchmarkError(
                "BoringSSL SHA-256 was not compiled with Release portable flags"
            )

    worker = build_root / "boringssl-sha256-worker.wasm"
    worker_command = [
        str(paths["clang++"]),
        f"--target={TARGET_TRIPLE}",
        f"--sysroot={sdk['sdkRoot']}",
        "-resource-dir",
        str(sdk["clangResourceDirectory"]),
        "-std=c++17",
        "-O3",
        "-DNDEBUG",
        "-fno-exceptions",
        "-fno-rtti",
        "-DOPENSSL_NO_ASM",
        f"-I{source / 'include'}",
        str(BORINGSSL_WORKER_SOURCE),
        str(archive),
        "-Wl,--gc-sections",
        "-o",
        str(worker),
    ]
    run_command(
        worker_command,
        cwd=REPOSITORY_ROOT,
        timeout_seconds=timeout_seconds,
    )
    if not worker.is_file():
        raise BenchmarkError("BoringSSL WASI worker was not linked")
    capability = run_wasm(
        paths["wasmkit"],
        worker,
        ("--capabilities",),
        timeout_seconds=30,
    ).stdout.strip()
    match = CAPABILITY_PATTERN.fullmatch(capability)
    if match is None or match.group(1) != "0":
        raise BenchmarkError(
            f"BoringSSL worker is not the portable backend: {capability}"
        )
    return worker, {
        "configureCommand": configure_command,
        "workerCommand": worker_command,
        "archive": str(archive),
        "worker": str(worker),
        "assemblyEnabled": False,
        "validatedCompileSources": [
            str(entry["file"]) for entry in sha_entries
        ],
    }


def build_swift_worker(
    *,
    sdk_id: str,
    build_root: Path,
    paths: dict[str, Path],
    sdk: dict[str, Path],
    timeout_seconds: int,
) -> tuple[Path, dict[str, Any]]:
    target_name = "embedded" if sdk_id == EMBEDDED_WASI_SDK else "wasi"
    scratch = build_root / f"swift-{target_name}"
    command = [
        "/usr/bin/xcrun",
        "swift",
        "build",
        "-c",
        "release",
        "--swift-sdk",
        sdk_id,
        "--product",
        "swift-ssl-sha256-benchmark",
        "--scratch-path",
        str(scratch),
        "-v",
    ]
    if sdk_id == EMBEDDED_WASI_SDK:
        if not sdk["unicodeDataTables"].is_file():
            raise BenchmarkError("Embedded Unicode data archive was not found")
        command.extend(
            [
                "-Xlinker",
                str(sdk["unicodeDataTables"]),
                "-Xlinker",
                "-lc++abi",
            ]
        )
    environment = inherited_environment(
        {
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
            "SWIFT_SSL_ENABLE_BENCHMARKS": "1",
        }
    )
    completed = run_command(
        command,
        cwd=REPOSITORY_ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    build_log = completed.stdout + completed.stderr
    required_fragments = (
        "-module-name SwiftSSLCrypto",
        "-module-name SwiftSSLSHA256Benchmark",
        f"-target {TARGET_TRIPLE}",
        " -O ",
        "-whole-module-optimization",
    )
    if any(fragment not in build_log for fragment in required_fragments):
        raise BenchmarkError("Swift build log did not prove the Release WASI path")
    if sdk_id == EMBEDDED_WASI_SDK and (
        "-enable-experimental-feature Embedded" not in build_log
    ):
        raise BenchmarkError("Swift build log did not prove Embedded mode")
    workers = list(
        scratch.glob(
            "out/Products/Release-webassembly-wasm32/"
            "swift-ssl-sha256-benchmark.wasm"
        )
    )
    if len(workers) != 1 or not workers[0].is_file():
        raise BenchmarkError("Swift WASI worker was not linked")
    return workers[0], {
        "sdkID": sdk_id,
        "sdkRoot": str(sdk["sdkRoot"]),
        "command": command,
        "worker": str(workers[0]),
    }


def run_wasm(
    wasmkit: Path,
    worker: Path,
    arguments: Sequence[str],
    *,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return run_command(
        [str(wasmkit), "run", str(worker), *arguments],
        timeout_seconds=timeout_seconds,
    )


def parse_result(stdout: str) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line]
    if len(lines) != 1:
        raise BenchmarkError("worker must emit exactly one nonempty result line")
    match = RESULT_PATTERN.fullmatch(lines[0])
    if match is None:
        raise BenchmarkError(f"malformed worker result: {lines[0]}")
    nanoseconds = int(match.group(1))
    if nanoseconds <= 0:
        raise BenchmarkError("worker reported a nonpositive duration")
    return {
        "measuredNanoseconds": nanoseconds,
        "checksum": int(match.group(2)),
        "digestHex": match.group(3),
    }


def run_worker(
    *,
    wasmkit: Path,
    worker: Path,
    byte_count: int,
    iterations: int,
    warmup_iterations: int,
    input_offset: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    completed = run_wasm(
        wasmkit,
        worker,
        (
            str(byte_count),
            str(iterations),
            str(warmup_iterations),
            str(input_offset),
        ),
        timeout_seconds=timeout_seconds,
    )
    result = parse_result(completed.stdout)
    result["wallNanoseconds"] = completed.wall_nanoseconds  # type: ignore[attr-defined]
    return result


def expected_digests(byte_count: int, iterations: int) -> list[str]:
    input_bytes = bytearray(
        ((index * 31 + 17) & 0xFF) for index in range(byte_count)
    )
    digests: list[str] = []
    for iteration in range(iterations):
        input_bytes[0] = iteration & 0xFF
        digests.append(hashlib.sha256(input_bytes).hexdigest())
    return digests


def validate_worker(
    *,
    wasmkit: Path,
    worker: Path,
    byte_count: int,
    input_offset: int,
    timeout_seconds: int,
) -> list[str]:
    iteration_count = 4
    completed = run_wasm(
        wasmkit,
        worker,
        (
            "--validate",
            str(byte_count),
            str(iteration_count),
            str(input_offset),
        ),
        timeout_seconds=timeout_seconds,
    )
    lines = [line for line in completed.stdout.splitlines() if line]
    if len(lines) != iteration_count:
        raise BenchmarkError("validation emitted an unexpected digest count")
    digests: list[str] = []
    for expected_iteration, line in enumerate(lines):
        match = DIGEST_PATTERN.fullmatch(line)
        if match is None or int(match.group(1)) != expected_iteration:
            raise BenchmarkError(f"malformed validation output: {line}")
        digests.append(match.group(2))
    if digests != expected_digests(byte_count, iteration_count):
        raise BenchmarkError(
            f"worker digest mismatch for {byte_count} bytes at offset {input_offset}"
        )
    return digests


def validate_pair(
    *,
    wasmkit: Path,
    swift_worker: Path,
    boringssl_worker: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for byte_count, input_offset in VALIDATION_CASES:
        swift = validate_worker(
            wasmkit=wasmkit,
            worker=swift_worker,
            byte_count=byte_count,
            input_offset=input_offset,
            timeout_seconds=timeout_seconds,
        )
        boringssl = validate_worker(
            wasmkit=wasmkit,
            worker=boringssl_worker,
            byte_count=byte_count,
            input_offset=input_offset,
            timeout_seconds=timeout_seconds,
        )
        if swift != boringssl:
            raise BenchmarkError("Swift and BoringSSL validation outputs differ")
        results.append(
            {
                "byteCount": byte_count,
                "inputOffset": input_offset,
                "digests": swift,
            }
        )
    return {
        "allDigestsMatched": True,
        "iterationCountPerCase": 4,
        "cases": results,
    }


def require_matching_results(
    swift: dict[str, Any],
    boringssl: dict[str, Any],
    *,
    context: str,
) -> None:
    swift_identity = (swift["checksum"], swift["digestHex"])
    boringssl_identity = (boringssl["checksum"], boringssl["digestHex"])
    if swift_identity != boringssl_identity:
        raise BenchmarkError(
            f"timed output mismatch in {context}: "
            f"Swift {swift_identity}, BoringSSL {boringssl_identity}"
        )


def warmup_iterations(iterations: int) -> int:
    return max(1, min(32, iterations // 8))


def calibrate(
    *,
    wasmkit: Path,
    swift_worker: Path,
    boringssl_worker: Path,
    byte_count: int,
    input_offset: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    iterations = 2
    rounds: list[dict[str, Any]] = []
    while iterations <= MAXIMUM_CALIBRATION_ITERATIONS:
        warmup = warmup_iterations(iterations)
        swift = run_worker(
            wasmkit=wasmkit,
            worker=swift_worker,
            byte_count=byte_count,
            iterations=iterations,
            warmup_iterations=warmup,
            input_offset=input_offset,
            timeout_seconds=timeout_seconds,
        )
        boringssl = run_worker(
            wasmkit=wasmkit,
            worker=boringssl_worker,
            byte_count=byte_count,
            iterations=iterations,
            warmup_iterations=warmup,
            input_offset=input_offset,
            timeout_seconds=timeout_seconds,
        )
        require_matching_results(swift, boringssl, context="calibration")
        minimum = min(
            swift["measuredNanoseconds"],
            boringssl["measuredNanoseconds"],
        )
        rounds.append(
            {
                "iterations": iterations,
                "warmupIterations": warmup,
                "minimumMeasuredNanoseconds": minimum,
            }
        )
        if minimum >= MINIMUM_SAMPLE_NANOSECONDS:
            return {
                "iterations": iterations,
                "warmupIterations": warmup,
                "rounds": rounds,
                "criterionNanoseconds": MINIMUM_SAMPLE_NANOSECONDS,
            }
        scale = max(
            2,
            math.ceil(MINIMUM_SAMPLE_NANOSECONDS / max(1, minimum) * 1.05),
        )
        iterations *= scale
    raise BenchmarkError("calibration exceeded its iteration limit")


def balanced_orders(sample_count: int, seed: int) -> list[str]:
    generator = random.Random(seed)
    orders = ["swift-boringssl"] * (sample_count // 2)
    orders.extend(["boringssl-swift"] * (sample_count // 2))
    if sample_count % 2:
        orders.append(generator.choice(("swift-boringssl", "boringssl-swift")))
    generator.shuffle(orders)
    return orders


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise BenchmarkError("cannot summarize an empty sample")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def bootstrap_interval(
    values: Sequence[float],
    *,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    if not values:
        raise BenchmarkError("cannot bootstrap an empty sample")
    generator = random.Random(seed)
    medians: list[float] = []
    for _ in range(resamples):
        sample = [
            values[generator.randrange(len(values))] for _ in range(len(values))
        ]
        medians.append(statistics.median(sample))
    return {
        "method": "paired-percentile-bootstrap-of-median-speedup",
        "confidenceLevel": 0.95,
        "resamples": resamples,
        "lower": percentile(medians, 0.025),
        "upper": percentile(medians, 0.975),
    }


def target_decision(interval: dict[str, Any]) -> str:
    if interval["lower"] >= TARGET_SPEEDUP:
        return "pass"
    if interval["upper"] < TARGET_SPEEDUP:
        return "fail"
    return "inconclusive"


def measure_workload(
    *,
    wasmkit: Path,
    swift_worker: Path,
    boringssl_worker: Path,
    workload: dict[str, Any],
    calibration: dict[str, Any],
    sample_count: int,
    bootstrap_resamples: int,
    seed: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    orders = balanced_orders(sample_count, seed)
    samples: list[dict[str, Any]] = []
    for pair_index, order in enumerate(orders):
        implementations = (
            ("swift", swift_worker),
            ("boringSSL", boringssl_worker),
        )
        if order == "boringssl-swift":
            implementations = tuple(reversed(implementations))
        results: dict[str, dict[str, Any]] = {}
        for implementation, worker in implementations:
            results[implementation] = run_worker(
                wasmkit=wasmkit,
                worker=worker,
                byte_count=workload["byteCount"],
                iterations=calibration["iterations"],
                warmup_iterations=calibration["warmupIterations"],
                input_offset=workload["inputOffset"],
                timeout_seconds=timeout_seconds,
            )
        require_matching_results(
            results["swift"],
            results["boringSSL"],
            context=f"{workload['name']} pair {pair_index}",
        )
        speedup = (
            results["boringSSL"]["measuredNanoseconds"]
            / results["swift"]["measuredNanoseconds"]
        )
        samples.append(
            {
                "pairIndex": pair_index,
                "order": order,
                "swift": results["swift"],
                "boringSSL": results["boringSSL"],
                "speedup": speedup,
            }
        )

    speedups = [sample["speedup"] for sample in samples]
    interval = bootstrap_interval(
        speedups,
        resamples=bootstrap_resamples,
        seed=seed ^ 0x534841323536,
    )
    swift_per_operation = [
        sample["swift"]["measuredNanoseconds"] / calibration["iterations"]
        for sample in samples
    ]
    boringssl_per_operation = [
        sample["boringSSL"]["measuredNanoseconds"] / calibration["iterations"]
        for sample in samples
    ]
    return {
        **workload,
        "calibration": calibration,
        "samples": samples,
        "statistics": {
            "swiftMedianNanosecondsPerOperation": statistics.median(
                swift_per_operation
            ),
            "boringSSLMedianNanosecondsPerOperation": statistics.median(
                boringssl_per_operation
            ),
            "pairedMedianSpeedup": statistics.median(speedups),
            "pairedSpeedupP05": percentile(speedups, 0.05),
            "pairedSpeedupP95": percentile(speedups, 0.95),
            "confidenceInterval95": interval,
        },
        "target": {
            "minimumSpeedup": TARGET_SPEEDUP,
            "criterion": (
                "lower bound of paired median speedup 95% bootstrap "
                "confidence interval is at least 1.10"
            ),
            "decision": target_decision(interval),
        },
    }


def selected_sdks(selection: str) -> tuple[str, ...]:
    if selection == "wasi":
        return (WASI_SDK,)
    if selection == "embedded":
        return (EMBEDDED_WASI_SDK,)
    return (WASI_SDK, EMBEDDED_WASI_SDK)


def output_path(selected: Path | None) -> Path:
    if selected is not None:
        return selected.resolve()
    return (
        REPOSITORY_ROOT
        / ".test-artifacts"
        / "benchmark"
        / f"{utc_timestamp()}-sha256-wasm.json"
    )


def main() -> int:
    options = build_argument_parser().parse_args()
    if options.bootstrap_resamples < MINIMUM_BOOTSTRAP_RESAMPLES:
        raise BenchmarkError(
            f"--bootstrap-resamples must be at least {MINIMUM_BOOTSTRAP_RESAMPLES}"
        )
    if options.formal and options.samples < MINIMUM_FORMAL_SAMPLES:
        raise BenchmarkError(
            f"formal measurement requires at least {MINIMUM_FORMAL_SAMPLES} pairs"
        )

    source_identity = repository_identity(REPOSITORY_ROOT)
    boringssl_identity = require_boringssl_source(options.boringssl_source)
    paths = toolchain_paths()
    compiler = compiler_identity(paths)
    if options.formal:
        if not source_identity["clean"]:
            raise BenchmarkError("formal measurement requires a clean Swift source")
        if not compiler["compilerCommitMatched"]:
            raise BenchmarkError("formal measurement requires the pinned compiler")

    build_root = make_build_root(options.build_root)
    ordinary_sdk = sdk_configuration(WASI_SDK)
    boringssl_worker, boringssl_build = build_boringssl(
        source=options.boringssl_source.resolve(),
        build_root=build_root,
        paths=paths,
        sdk=ordinary_sdk,
        timeout_seconds=options.build_timeout_seconds,
    )

    target_results: list[dict[str, Any]] = []
    for target_index, sdk_id in enumerate(selected_sdks(options.target)):
        sdk = sdk_configuration(sdk_id)
        swift_worker, swift_build = build_swift_worker(
            sdk_id=sdk_id,
            build_root=build_root,
            paths=paths,
            sdk=sdk,
            timeout_seconds=options.build_timeout_seconds,
        )
        validation = validate_pair(
            wasmkit=paths["wasmkit"],
            swift_worker=swift_worker,
            boringssl_worker=boringssl_worker,
            timeout_seconds=options.worker_timeout_seconds,
        )
        workloads: list[dict[str, Any]] = []
        for workload_index, workload in enumerate(WORKLOADS):
            calibration = calibrate(
                wasmkit=paths["wasmkit"],
                swift_worker=swift_worker,
                boringssl_worker=boringssl_worker,
                byte_count=workload["byteCount"],
                input_offset=workload["inputOffset"],
                timeout_seconds=options.worker_timeout_seconds,
            )
            result = measure_workload(
                wasmkit=paths["wasmkit"],
                swift_worker=swift_worker,
                boringssl_worker=boringssl_worker,
                workload=workload,
                calibration=calibration,
                sample_count=options.samples,
                bootstrap_resamples=options.bootstrap_resamples,
                seed=options.seed ^ (target_index << 24) ^ workload_index,
                timeout_seconds=options.worker_timeout_seconds,
            )
            workloads.append(result)
            statistics_result = result["statistics"]
            interval = statistics_result["confidenceInterval95"]
            print(
                f"{sdk_id} {workload['name']}: "
                f"{statistics_result['pairedMedianSpeedup']:.4f}x "
                f"[{interval['lower']:.4f}, {interval['upper']:.4f}] "
                f"{result['target']['decision']}"
            )
        target_results.append(
            {
                "sdkID": sdk_id,
                "swiftBuild": swift_build,
                "validation": validation,
                "workloads": workloads,
                "decision": (
                    "pass"
                    if all(
                        result["target"]["decision"] == "pass"
                        for result in workloads
                    )
                    else (
                        "fail"
                        if any(
                            result["target"]["decision"] == "fail"
                            for result in workloads
                        )
                        else "inconclusive"
                    )
                ),
            }
        )

    final_source_identity = repository_identity(REPOSITORY_ROOT)
    if options.formal and final_source_identity != source_identity:
        raise BenchmarkError("Swift repository changed during formal measurement")
    overall = (
        "pass"
        if all(target["decision"] == "pass" for target in target_results)
        else (
            "fail"
            if any(target["decision"] == "fail" for target in target_results)
            else "inconclusive"
        )
    )
    artifact = {
        "schemaVersion": 1,
        "createdAtUTC": datetime_module.datetime.now(
            datetime_module.timezone.utc
        ).isoformat(),
        "evidenceClass": "formal" if options.formal else "exploratory",
        "source": source_identity,
        "boringSSL": boringssl_identity,
        "compiler": compiler,
        "runtime": {
            "executable": str(paths["wasmkit"]),
            "version": run_command(
                [str(paths["wasmkit"]), "--version"],
                timeout_seconds=30,
            ).stdout.strip(),
        },
        "buildRoot": str(build_root),
        "boringSSLBuild": boringssl_build,
        "sampling": {
            "pairedSamplesPerWorkload": options.samples,
            "bootstrapResamples": options.bootstrap_resamples,
            "seed": options.seed,
        },
        "targets": target_results,
        "targetCriterion": {
            "minimumSpeedup": TARGET_SPEEDUP,
            "scope": (
                "portable no-assembly BoringSSL on sustained one-shot "
                "1 MiB WASI workloads"
            ),
        },
        "decision": overall,
    }
    selected_output = output_path(options.output)
    selected_output.parent.mkdir(parents=True, exist_ok=True)
    selected_output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"artifact: {selected_output}")
    print(f"overall: {overall}")
    if (options.formal or options.enforce_target) and overall != "pass":
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        raise SystemExit(2)
