#!/usr/bin/env python3
"""Build and compare Pure Swift and BoringSSL X25519MLKEM768 key shares."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import select
import shlex
import statistics
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parents[1]
SUPPORT_PATH = SCRIPT_DIRECTORY.parent / "MLKEM" / "run_comparison.py"
SUPPORT_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_benchmark_support",
    SUPPORT_PATH,
)
if SUPPORT_SPEC is None or SUPPORT_SPEC.loader is None:
    raise RuntimeError("could not load shared benchmark support")
support = importlib.util.module_from_spec(SUPPORT_SPEC)
SUPPORT_SPEC.loader.exec_module(support)


BenchmarkError = support.BenchmarkError
EXPECTED_BORINGSSL_COMMIT = support.EXPECTED_BORINGSSL_COMMIT
EXPECTED_BORINGSSL_ORIGIN = support.EXPECTED_BORINGSSL_ORIGIN
EXPECTED_SWIFT_TOOLCHAIN = support.EXPECTED_SWIFT_TOOLCHAIN
EXPECTED_SWIFT_COMPILER_COMMIT = support.EXPECTED_SWIFT_COMPILER_COMMIT
EXPECTED_ARCHITECTURE = support.EXPECTED_ARCHITECTURE
EXPECTED_MACOS_SDK_VERSION = support.EXPECTED_MACOS_SDK_VERSION
SWIFT_BUILD_TRIPLE = support.SWIFT_BUILD_TRIPLE
DEPLOYMENT_TARGET = support.DEPLOYMENT_TARGET
TARGET_SPEEDUP = 1.10
MINIMUM_SAMPLE_COUNT = 30
MINIMUM_SAMPLE_NANOSECONDS = 200_000_000
MAXIMUM_CALIBRATION_ROUNDS = 8
CONVERGENCE_WINDOW = 3
MAXIMUM_CONVERGENCE_ROUNDS = 10
CONVERGENCE_TOLERANCE = 0.05
DEFAULT_QUIESCENCE_TIMEOUT_SECONDS = support.DEFAULT_QUIESCENCE_TIMEOUT_SECONDS
INITIAL_ITERATIONS = 4_000
OPERATION = "roundtrip"
RESULT_PATTERN = re.compile(r"^RESULT,([0-9]+),([0-9]+)$")
CLIENT_PATTERN = re.compile(r"^CLIENT,([0-9a-f]{2432})$")
SERVER_PATTERN = re.compile(r"^SERVER,([0-9a-f]{2240}),([0-9a-f]{128})$")
SECRET_PATTERN = re.compile(r"^SECRET,([0-9a-f]{128})$")


def parse_positive_integer(value: str) -> int:
    return support.parse_positive_integer(value)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build and compare Pure Swift and pinned BoringSSL "
            "X25519MLKEM768 key-share round trips."
        )
    )
    parser.add_argument(
        "--boringssl-source",
        required=True,
        type=Path,
        help="Path to the clean pinned official BoringSSL checkout.",
    )
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=parse_positive_integer, default=30)
    parser.add_argument(
        "--bootstrap-resamples",
        type=parse_positive_integer,
        default=10_000,
    )
    parser.add_argument("--seed", type=int)
    parser.add_argument(
        "--worker-timeout-seconds",
        type=parse_positive_integer,
        default=120,
    )
    parser.add_argument(
        "--build-timeout-seconds",
        type=parse_positive_integer,
        default=1_800,
    )
    parser.add_argument(
        "--quiescence-timeout-seconds",
        type=parse_positive_integer,
        default=DEFAULT_QUIESCENCE_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--formal",
        action="store_true",
        help="Require clean committed sources and read-only Git snapshots.",
    )
    return parser


def parse_worker_result(stdout: str, stderr: str) -> dict[str, int]:
    if stderr:
        raise BenchmarkError(f"worker wrote to standard error: {stderr.strip()}")
    if not stdout.endswith("\n") or stdout.count("\n") != 1:
        raise BenchmarkError(f"invalid worker result: {stdout!r}")
    match = RESULT_PATTERN.fullmatch(stdout[:-1])
    if match is None:
        raise BenchmarkError(f"invalid worker result: {stdout!r}")
    nanoseconds = int(match.group(1), 10)
    checksum = int(match.group(2), 10)
    if nanoseconds <= 0:
        raise BenchmarkError("worker reported a non-positive duration")
    return {"nanoseconds": nanoseconds, "checksum": checksum}


def parse_client_record(record: str) -> str:
    match = CLIENT_PATTERN.fullmatch(record)
    if match is None:
        raise BenchmarkError("invalid X25519MLKEM768 client key-share record")
    return match.group(1)


def parse_server_record(record: str) -> tuple[str, str]:
    match = SERVER_PATTERN.fullmatch(record)
    if match is None:
        raise BenchmarkError("invalid X25519MLKEM768 server key-share record")
    return match.group(1), match.group(2)


def parse_secret_record(record: str) -> str:
    match = SECRET_PATTERN.fullmatch(record)
    if match is None:
        raise BenchmarkError("invalid X25519MLKEM768 shared-secret record")
    return match.group(1)


def invoke_worker(
    worker: Path,
    iterations: int,
    warmup_iterations: int,
    timeout_seconds: int,
) -> dict[str, int]:
    completed = support.run_command(
        [str(worker), OPERATION, str(iterations), str(warmup_iterations)],
        cwd=worker.parent,
        timeout_seconds=timeout_seconds,
    )
    return parse_worker_result(completed.stdout, completed.stderr)


def invoke_validation(worker: Path, arguments: Sequence[str]) -> str:
    completed = support.run_command(
        [str(worker), *arguments],
        cwd=worker.parent,
        timeout_seconds=30,
    )
    if completed.stderr:
        raise BenchmarkError(
            f"interoperability worker wrote to standard error: {completed.stderr.strip()}"
        )
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise BenchmarkError("interoperability worker did not return one record")
    return lines[0]


def run_interactive_boringssl_client(
    boringssl_worker: Path,
    swift_worker: Path,
) -> dict[str, str]:
    process = subprocess.Popen(
        [str(boringssl_worker), "interop-client"],
        cwd=boringssl_worker.parent,
        env=support.sanitized_environment(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdout is None or process.stdin is None or process.stderr is None:
        process.kill()
        raise BenchmarkError("could not create BoringSSL interoperability pipes")
    readable, _, _ = select.select([process.stdout], [], [], 30)
    if not readable:
        process.kill()
        process.wait(timeout=5)
        raise BenchmarkError("BoringSSL client did not emit a key share")
    client_share = parse_client_record(process.stdout.readline().rstrip("\n"))
    server_record = invoke_validation(swift_worker, ["interop-server", client_share])
    server_share, swift_secret = parse_server_record(server_record)
    try:
        stdout, stderr = process.communicate(server_share + "\n", timeout=30)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise BenchmarkError("BoringSSL client did not complete") from error
    if process.returncode != 0 or stderr:
        detail = stderr.strip() or f"status {process.returncode}"
        raise BenchmarkError(f"BoringSSL client failed: {detail}")
    boringssl_secret = parse_secret_record(stdout.strip())
    if swift_secret != boringssl_secret:
        raise BenchmarkError("BoringSSL client and Swift server derived different secrets")
    return {
        "clientShareSHA256": hashlib.sha256(bytes.fromhex(client_share)).hexdigest(),
        "serverShareSHA256": hashlib.sha256(bytes.fromhex(server_share)).hexdigest(),
        "sharedSecretSHA256": hashlib.sha256(bytes.fromhex(swift_secret)).hexdigest(),
    }


def validate_interoperability(
    swift_worker: Path,
    boringssl_worker: Path,
) -> dict[str, Any]:
    swift_client_share = parse_client_record(
        invoke_validation(swift_worker, ["interop-client-offer"])
    )
    server_share, boringssl_secret = parse_server_record(
        invoke_validation(
            boringssl_worker,
            ["interop-server", swift_client_share],
        )
    )
    swift_secret = parse_secret_record(
        invoke_validation(
            swift_worker,
            ["interop-client-complete", server_share],
        )
    )
    if swift_secret != boringssl_secret:
        raise BenchmarkError("Swift client and BoringSSL server derived different secrets")
    swift_client = {
        "clientShareSHA256": hashlib.sha256(
            bytes.fromhex(swift_client_share)
        ).hexdigest(),
        "serverShareSHA256": hashlib.sha256(bytes.fromhex(server_share)).hexdigest(),
        "sharedSecretSHA256": hashlib.sha256(bytes.fromhex(swift_secret)).hexdigest(),
    }
    return {
        "group": "X25519MLKEM768",
        "namedGroup": "0x11ec",
        "clientShareBytes": 1_216,
        "serverShareBytes": 1_120,
        "sharedSecretBytes": 64,
        "swiftClientBoringSSLServer": swift_client,
        "boringSSLClientSwiftServer": run_interactive_boringssl_client(
            boringssl_worker,
            swift_worker,
        ),
        "passed": True,
    }


def inspect_worker_codegen(
    swift_worker: Path,
    boringssl_worker: Path,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    environment = support.sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    swift_symbols = support.run_command(
        [toolchain["tools"]["nm"], "-nm", str(swift_worker)],
        cwd=swift_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    required_swift_symbols = (
        "X25519FieldElement",
        "MLKEM768O15generateKeyPair",
        "TLS13X25519MLKEM768ClientKeyExchange",
        "TLS13X25519MLKEM768ServerKeyExchange",
    )
    missing_swift = [symbol for symbol in required_swift_symbols if symbol not in swift_symbols]
    if missing_swift:
        raise BenchmarkError(f"Swift hybrid symbols are missing: {missing_swift}")
    swift_disassembly = support.run_command(
        [toolchain["tools"]["otool"], "-tvV", str(swift_worker)],
        cwd=swift_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    multiply_high_count = len(re.findall(r"\bumulh\b", swift_disassembly))
    carry_count = len(re.findall(r"\badc\b", swift_disassembly))
    if multiply_high_count < 100 or carry_count < 100:
        raise BenchmarkError("Swift UInt128 field-arithmetic code generation is missing")
    undefined_swift = support.run_command(
        [toolchain["tools"]["nm"], "-u", str(swift_worker)],
        cwd=swift_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    forbidden_dependencies = re.findall(
        r"(?im)^.*(?:BoringSSL|SSLKeyShare|MLKEM(?:768|1024)_|X25519_).*$",
        undefined_swift,
    )
    if forbidden_dependencies:
        raise BenchmarkError(
            f"Swift worker imports external crypto symbols: {forbidden_dependencies}"
        )

    boringssl_symbols = support.run_command(
        [toolchain["tools"]["nm"], "-nm", str(boringssl_worker)],
        cwd=boringssl_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    required_boringssl_symbols = (
        "X25519MLKEM768KeyShare",
        "_MLKEM768_generate_key",
        "_MLKEM768_encap",
        "_MLKEM768_decap",
        "_X25519_public_from_private",
    )
    missing_boringssl = [
        symbol for symbol in required_boringssl_symbols if symbol not in boringssl_symbols
    ]
    if missing_boringssl:
        raise BenchmarkError(f"BoringSSL hybrid symbols are missing: {missing_boringssl}")
    return {
        "swift": {
            "symbolTableSHA256": hashlib.sha256(swift_symbols.encode()).hexdigest(),
            "disassemblySHA256": hashlib.sha256(swift_disassembly.encode()).hexdigest(),
            "uint128MultiplyHighInstructionCount": multiply_high_count,
            "carryInstructionCount": carry_count,
            "externalCryptoImports": [],
            "passed": True,
        },
        "boringSSL": {
            "symbolTableSHA256": hashlib.sha256(boringssl_symbols.encode()).hexdigest(),
            "requiredSymbols": list(required_boringssl_symbols),
            "passed": True,
        },
    }


def build_workers(
    *,
    swift_source: Path,
    boringssl_source: Path,
    build_root: Path,
    build_timeout_seconds: int,
    toolchain: dict[str, Any],
) -> tuple[Path, Path, dict[str, Any]]:
    swift_scratch = build_root / "swift-build"
    swift_cache = build_root / "swift-cache"
    swift_environment = support.sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "SDKROOT": toolchain["macOSSDKPath"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
            "SWIFT_SSL_ENABLE_BENCHMARKS": "1",
        }
    )
    swift_command = [
        toolchain["tools"]["swift"],
        "build",
        "--build-system",
        "native",
        "--disable-dependency-cache",
        "--disable-build-manifest-caching",
        "--cache-path",
        str(swift_cache),
        "--scratch-path",
        str(swift_scratch),
        "--configuration",
        "release",
        "--triple",
        SWIFT_BUILD_TRIPLE,
        "--sdk",
        toolchain["macOSSDKPath"],
        "--jobs",
        "2",
        "--product",
        "swift-ssl-tls-hybrid-benchmark",
        "-v",
    ]
    swift_build = support.run_command(
        swift_command,
        cwd=swift_source,
        timeout_seconds=build_timeout_seconds,
        environment=swift_environment,
    )
    swift_worker = support.locate_single_executable(
        swift_scratch,
        "swift-ssl-tls-hybrid-benchmark",
    )

    cmake = shutil_which("cmake", swift_environment["PATH"])
    ninja = shutil_which("ninja", swift_environment["PATH"])
    boringssl_build_root = build_root / "boringssl-build"
    driver_source = swift_source / "Benchmarks/TLSHybrid/BoringSSLDriver"
    configure_command = [
        cmake,
        "-S",
        str(driver_source),
        "-B",
        str(boringssl_build_root),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_OSX_ARCHITECTURES={EXPECTED_ARCHITECTURE}",
        f"-DCMAKE_OSX_DEPLOYMENT_TARGET={DEPLOYMENT_TARGET}",
        f"-DCMAKE_OSX_SYSROOT={toolchain['macOSSDKPath']}",
        f"-DCMAKE_C_COMPILER={toolchain['tools']['clang']}",
        f"-DCMAKE_CXX_COMPILER={toolchain['tools']['clang++']}",
        "-DCMAKE_CXX_COMPILER_ARG1=--driver-mode=g++",
        f"-DCMAKE_ASM_COMPILER={toolchain['tools']['clang']}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DCMAKE_MAKE_PROGRAM={ninja}",
        f"-DBORINGSSL_SOURCE={boringssl_source}",
        f"-DBORINGSSL_COMMIT={EXPECTED_BORINGSSL_COMMIT}",
    ]
    configure = support.run_command(
        configure_command,
        cwd=swift_source,
        timeout_seconds=build_timeout_seconds,
        environment=swift_environment,
    )
    build_command = [
        cmake,
        "--build",
        str(boringssl_build_root),
        "--target",
        "boringssl-tls-hybrid-benchmark",
        "--",
        "-v",
    ]
    boringssl_build = support.run_command(
        build_command,
        cwd=build_root,
        timeout_seconds=build_timeout_seconds,
        environment=swift_environment,
    )
    boringssl_worker = support.locate_single_executable(
        boringssl_build_root,
        "boringssl-tls-hybrid-benchmark",
    )

    swift_log = swift_build.stdout + "\n" + swift_build.stderr
    for module in (
        "SSLCore",
        "SSLCrypto",
        "SSLASN1",
        "SSLX509",
        "SSLTLS",
        "SSLTLSHybridBenchmark",
    ):
        lines = [line for line in swift_log.splitlines() if f"-module-name {module}" in line]
        if not lines or not any(
            " -O " in f" {line} "
            and f"-target {SWIFT_BUILD_TRIPLE}" in line
            and f"-sdk {toolchain['macOSSDKPath']}" in line
            for line in lines
        ):
            raise BenchmarkError(f"Swift build contract mismatch for {module}")
    forbidden_swift_flags = ("-Onone", "-sanitize=", "-profile-generate")
    if any(flag in swift_log for flag in forbidden_swift_flags):
        raise BenchmarkError("Swift build contains a forbidden instrumentation flag")

    compile_database_path = boringssl_build_root / "compile_commands.json"
    cache_path = boringssl_build_root / "CMakeCache.txt"
    if not compile_database_path.is_file() or not cache_path.is_file():
        raise BenchmarkError("BoringSSL build metadata is incomplete")
    compile_database = json.loads(compile_database_path.read_text(encoding="utf-8"))
    compiled_files = {Path(entry["file"]).resolve() for entry in compile_database}
    required_sources = {
        (driver_source / "TLSHybridBenchmark.cpp").resolve(),
        (boringssl_source / "ssl/ssl_key_share.cc").resolve(),
        (boringssl_source / "crypto/fipsmodule/bcm.cc").resolve(),
    }
    missing_sources = required_sources - compiled_files
    if missing_sources:
        raise BenchmarkError(
            f"BoringSSL required sources were not compiled: {sorted(map(str, missing_sources))}"
        )
    for entry in compile_database:
        command = entry.get("command") or " ".join(entry.get("arguments", []))
        arguments = shlex.split(command)
        if "-O3" not in arguments or "-DNDEBUG" not in arguments:
            raise BenchmarkError(f"BoringSSL source is not Release: {entry['file']}")
        if any(
            argument.startswith(("-fsanitize", "-fprofile"))
            or argument in ("-DOPENSSL_NO_ASM", "-DOPENSSL_NO_ASM=1")
            for argument in arguments
        ):
            raise BenchmarkError("BoringSSL build violates the benchmark contract")
    if "OPENSSL_NO_ASM:BOOL=OFF" not in cache_path.read_text(encoding="utf-8"):
        raise BenchmarkError("BoringSSL assembly is disabled")

    workers = {
        "swift": worker_metadata(swift_worker, toolchain),
        "boringSSL": worker_metadata(boringssl_worker, toolchain),
    }
    return swift_worker, boringssl_worker, {
        "swift": {
            "command": swift_command,
            "stdoutSHA256": hashlib.sha256(swift_build.stdout.encode()).hexdigest(),
            "stderr": swift_build.stderr,
            "validatedModules": [
                "SSLCore",
                "SSLCrypto",
                "SSLASN1",
                "SSLX509",
                "SSLTLS",
                "SSLTLSHybridBenchmark",
            ],
            "passed": True,
        },
        "boringSSLConfigure": {
            "command": configure_command,
            "stdout": configure.stdout,
            "stderr": configure.stderr,
        },
        "boringSSLBuild": {
            "command": build_command,
            "stdoutSHA256": hashlib.sha256(boringssl_build.stdout.encode()).hexdigest(),
            "stderr": boringssl_build.stderr,
        },
        "boringSSLCompileDatabase": {
            "path": str(compile_database_path),
            "sha256": support.file_sha256(compile_database_path),
            "entryCount": len(compile_database),
            "requiredSources": sorted(map(str, required_sources)),
            "assemblyEnabled": True,
            "passed": True,
        },
        "workers": workers,
        "codeGeneration": inspect_worker_codegen(
            swift_worker,
            boringssl_worker,
            toolchain,
        ),
    }


def shutil_which(name: str, search_path: str) -> str:
    import shutil

    path = shutil.which(name, path=search_path)
    if path is None:
        raise BenchmarkError(f"{name} is required")
    return path


def worker_metadata(path: Path, toolchain: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": support.file_sha256(path),
        "sizeBytes": path.stat().st_size,
        "machO": support.collect_macho_metadata(path, toolchain),
    }


def convergence_reached(values: Sequence[float]) -> bool:
    if len(values) < CONVERGENCE_WINDOW:
        return False
    window = values[-CONVERGENCE_WINDOW:]
    center = statistics.median(window)
    return all(abs(value - center) / center <= CONVERGENCE_TOLERANCE for value in window)


def calibrate(
    swift_worker: Path,
    boringssl_worker: Path,
    timeout_seconds: int,
) -> tuple[int, list[dict[str, Any]]]:
    iterations = INITIAL_ITERATIONS
    pilots: list[dict[str, Any]] = []
    for _ in range(MAXIMUM_CALIBRATION_ROUNDS):
        swift = invoke_worker(swift_worker, iterations, 1_000, timeout_seconds)
        boring = invoke_worker(boringssl_worker, iterations, 1_000, timeout_seconds)
        pilots.append({"iterations": iterations, "swift": swift, "boringSSL": boring})
        fastest = min(swift["nanoseconds"], boring["nanoseconds"])
        if fastest >= MINIMUM_SAMPLE_NANOSECONDS:
            return iterations, pilots
        scale = max(2, (MINIMUM_SAMPLE_NANOSECONDS + fastest - 1) // fastest)
        iterations *= scale
    raise BenchmarkError("calibration did not reach the minimum sample duration")


def converge(
    swift_worker: Path,
    boringssl_worker: Path,
    iterations: int,
    timeout_seconds: int,
    quiescence_timeout_seconds: int,
    generator: random.Random,
) -> list[dict[str, Any]]:
    rounds: list[dict[str, Any]] = []
    swift_values: list[float] = []
    boring_values: list[float] = []
    for index in range(MAXIMUM_CONVERGENCE_ROUNDS):
        quiescence = support.wait_for_quiescence(quiescence_timeout_seconds)
        swift_first = bool(generator.randrange(2))
        if swift_first:
            swift = invoke_worker(swift_worker, iterations, 1_000, timeout_seconds)
            boring = invoke_worker(boringssl_worker, iterations, 1_000, timeout_seconds)
        else:
            boring = invoke_worker(boringssl_worker, iterations, 1_000, timeout_seconds)
            swift = invoke_worker(swift_worker, iterations, 1_000, timeout_seconds)
        swift_values.append(swift["nanoseconds"] / iterations)
        boring_values.append(boring["nanoseconds"] / iterations)
        rounds.append(
            {
                "index": index,
                "order": "swift-first" if swift_first else "boringssl-first",
                "swift": swift,
                "boringSSL": boring,
                "quiescence": quiescence,
            }
        )
        if convergence_reached(swift_values) and convergence_reached(boring_values):
            return rounds
    raise BenchmarkError("X25519MLKEM768 round-trip timing did not converge")


def balanced_orders(sample_count: int, generator: random.Random) -> list[str]:
    return support.balanced_orders(sample_count, generator)


def bootstrap_median_interval(
    values: Sequence[float],
    resamples: int,
    generator: random.Random,
) -> tuple[float, float]:
    return support.bootstrap_median_interval(values, resamples, generator)


def summarize_workload(
    samples: Sequence[dict[str, Any]],
    iterations: int,
    bootstrap_resamples: int,
    generator: random.Random,
) -> dict[str, Any]:
    swift_values = [sample["swift"]["nanoseconds"] / iterations for sample in samples]
    boring_values = [
        sample["boringSSL"]["nanoseconds"] / iterations for sample in samples
    ]
    paired_speedups = [
        boring / swift for boring, swift in zip(boring_values, swift_values)
    ]
    lower, upper = bootstrap_median_interval(
        paired_speedups,
        bootstrap_resamples,
        generator,
    )
    return {
        "operation": OPERATION,
        "iterationsPerSample": iterations,
        "swiftMedianNanosecondsPerOperation": statistics.median(swift_values),
        "swiftP95NanosecondsPerOperation": support.percentile(swift_values, 0.95),
        "boringSSLMedianNanosecondsPerOperation": statistics.median(boring_values),
        "boringSSLP95NanosecondsPerOperation": support.percentile(boring_values, 0.95),
        "medianPairedSpeedup": statistics.median(paired_speedups),
        "speedupConfidenceInterval95": [lower, upper],
        "targetSpeedup": TARGET_SPEEDUP,
        "passed": lower >= TARGET_SPEEDUP,
        "samples": list(samples),
    }


def main() -> int:
    arguments = build_argument_parser().parse_args()
    if arguments.samples < MINIMUM_SAMPLE_COUNT or arguments.samples % 2 != 0:
        raise BenchmarkError("samples must be even and at least 30")
    if arguments.bootstrap_resamples < 1_000:
        raise BenchmarkError("bootstrap resamples must be at least 1000")

    boringssl_source = arguments.boringssl_source.resolve()
    swift_metadata = support.git_metadata(REPOSITORY_ROOT)
    boringssl_metadata = support.git_metadata(boringssl_source)
    if boringssl_metadata["commit"] != EXPECTED_BORINGSSL_COMMIT:
        raise BenchmarkError("BoringSSL commit does not match the pinned baseline")
    if not boringssl_metadata["isClean"]:
        raise BenchmarkError("BoringSSL checkout must be clean")
    normalized_origin = (boringssl_metadata["origin"] or "").removesuffix(".git")
    if normalized_origin != EXPECTED_BORINGSSL_ORIGIN:
        raise BenchmarkError("BoringSSL origin does not match the official baseline")
    if arguments.formal and not swift_metadata["isClean"]:
        raise BenchmarkError("formal comparison requires a clean SSL checkout")
    if arguments.formal and os.environ.get("TOOLCHAINS") != EXPECTED_SWIFT_TOOLCHAIN:
        raise BenchmarkError(
            f"formal comparison requires TOOLCHAINS={EXPECTED_SWIFT_TOOLCHAIN}"
        )

    seed = arguments.seed
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    generator = random.Random(seed)
    bootstrap_generator = random.Random(seed ^ 0x5832_3535_3139_4D4B)

    output = arguments.output
    if output is None:
        output = SCRIPT_DIRECTORY / "Results" / (
            f"{support.utc_file_timestamp()}-native-x25519mlkem768.json"
        )
    output = output.resolve()
    if output.exists():
        raise BenchmarkError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    build_root = arguments.build_root
    if build_root is None:
        parent = REPOSITORY_ROOT / ".build" / "benchmark-tls-hybrid"
        parent.mkdir(parents=True, exist_ok=True)
        build_root = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    else:
        build_root = build_root.resolve()
        if build_root.exists():
            raise BenchmarkError(f"build root already exists: {build_root}")
        build_root.mkdir(parents=True)

    environment = support.collect_toolchain_metadata()
    swift_source = REPOSITORY_ROOT
    selected_boringssl_source = boringssl_source
    snapshots: dict[str, Any] | None = None
    if arguments.formal:
        snapshots_root = build_root / "sources"
        snapshots_root.mkdir()
        swift_source = snapshots_root / "swift-ssl"
        selected_boringssl_source = snapshots_root / "boringssl"
        snapshots = {
            "ssl": support.make_snapshot(
                REPOSITORY_ROOT,
                swift_metadata["commit"],
                swift_source,
            ),
            "boringSSL": support.make_snapshot(
                boringssl_source,
                boringssl_metadata["commit"],
                selected_boringssl_source,
            ),
        }

    swift_worker, boringssl_worker, build_evidence = build_workers(
        swift_source=swift_source,
        boringssl_source=selected_boringssl_source,
        build_root=build_root,
        build_timeout_seconds=arguments.build_timeout_seconds,
        toolchain=environment,
    )
    worker_evidence = build_evidence["workers"]
    post_build_quiescence = support.wait_for_quiescence(
        arguments.quiescence_timeout_seconds
    )
    interoperability = validate_interoperability(swift_worker, boringssl_worker)
    iterations, calibration = calibrate(
        swift_worker,
        boringssl_worker,
        arguments.worker_timeout_seconds,
    )
    convergence = converge(
        swift_worker,
        boringssl_worker,
        iterations,
        arguments.worker_timeout_seconds,
        arguments.quiescence_timeout_seconds,
        generator,
    )

    samples: list[dict[str, Any]] = []
    for index, order in enumerate(balanced_orders(arguments.samples, generator)):
        quiescence = support.wait_for_quiescence(
            arguments.quiescence_timeout_seconds
        )
        if order == "swift-first":
            swift = invoke_worker(swift_worker, iterations, 1_000, arguments.worker_timeout_seconds)
            boring = invoke_worker(
                boringssl_worker, iterations, 1_000, arguments.worker_timeout_seconds
            )
        else:
            boring = invoke_worker(
                boringssl_worker, iterations, 1_000, arguments.worker_timeout_seconds
            )
            swift = invoke_worker(swift_worker, iterations, 1_000, arguments.worker_timeout_seconds)
        samples.append(
            {
                "index": index,
                "order": order,
                "swift": swift,
                "boringSSL": boring,
                "quiescence": quiescence,
            }
        )

    result = {
        "calibration": calibration,
        "convergence": convergence,
        **summarize_workload(
            samples,
            iterations,
            arguments.bootstrap_resamples,
            bootstrap_generator,
        ),
    }
    final_swift_metadata = support.git_metadata(REPOSITORY_ROOT)
    final_boringssl_metadata = support.git_metadata(boringssl_source)
    if final_swift_metadata != swift_metadata:
        raise BenchmarkError("SSL repository identity changed during comparison")
    if final_boringssl_metadata != boringssl_metadata:
        raise BenchmarkError("BoringSSL repository identity changed during comparison")
    if support.file_sha256(swift_worker) != worker_evidence["swift"]["sha256"]:
        raise BenchmarkError("Swift worker changed during comparison")
    if support.file_sha256(boringssl_worker) != worker_evidence["boringSSL"]["sha256"]:
        raise BenchmarkError("BoringSSL worker changed during comparison")
    final_snapshot_evidence: dict[str, Any] | None = None
    if snapshots is not None:
        final_snapshot_evidence = {}
        for name, snapshot in snapshots.items():
            archive_hash = support.file_sha256(Path(snapshot["archivePath"]))
            tree_hash = support.tree_sha256(Path(snapshot["path"]))
            if archive_hash != snapshot["archiveSHA256"] or tree_hash != snapshot["treeSHA256"]:
                raise BenchmarkError(f"{name} source snapshot changed during comparison")
            final_snapshot_evidence[name] = {
                "archiveSHA256": archive_hash,
                "treeSHA256": tree_hash,
                "unchanged": True,
            }
    final_quiescence = support.wait_for_quiescence(
        arguments.quiescence_timeout_seconds
    )
    artifact = {
        "schemaVersion": 1,
        "classification": "formal" if arguments.formal else "exploratory",
        "valid": True,
        "passed": result["passed"],
        "targetSpeedup": TARGET_SPEEDUP,
        "seed": seed,
        "sampleCount": arguments.samples,
        "bootstrapResamples": arguments.bootstrap_resamples,
        "environment": environment,
        "finalToolIdentities": support.verify_executable_identities(
            environment["toolIdentities"]
        ),
        "sources": {
            "ssl": swift_metadata,
            "boringSSL": boringssl_metadata,
            "snapshots": snapshots,
        },
        "buildRoot": str(build_root),
        "build": build_evidence,
        "workers": worker_evidence,
        "interoperability": interoperability,
        "zeroCopyContract": {
            "clientInput": "borrowed Span",
            "serverInput": "borrowed Span",
            "serializedPublicKeys": "caller-owned MutableSpan",
            "sharedSecret": "caller-owned SecretBytes storage",
            "allocationCountMeasured": False,
        },
        "quiescence": {"postBuild": post_build_quiescence, "final": final_quiescence},
        "finalSnapshotEvidence": final_snapshot_evidence,
        "result": result,
        "completedAt": support.utc_now(),
    }
    temporary_output = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary_output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    os.rename(temporary_output, output)
    interval = result["speedupConfidenceInterval95"]
    print(f"artifact: {output}")
    print(
        f"x25519mlkem768-roundtrip: {result['medianPairedSpeedup']:.4f}x "
        f"(95% CI {interval[0]:.4f}x...{interval[1]:.4f}x)"
    )
    print("decision: pass" if result["passed"] else "decision: target not established")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"invalid comparison: {error}", file=os.sys.stderr)
        raise SystemExit(2)
