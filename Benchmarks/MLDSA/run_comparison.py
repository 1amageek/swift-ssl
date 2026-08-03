#!/usr/bin/env python3
"""Build and compare Pure Swift and BoringSSL ML-DSA implementations."""

from __future__ import annotations

import argparse
import datetime as datetime_module
import hashlib
import json
import os
import platform
import random
import re
import shutil
import shlex
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


EXPECTED_BORINGSSL_COMMIT = "ae49d2681a56ca7b8609f6039a770fda2a8eb550"
EXPECTED_BORINGSSL_ORIGIN = "https://boringssl.googlesource.com/boringssl"
EXPECTED_SWIFT_TOOLCHAIN = "org.swift.64202607231a"
EXPECTED_SWIFT_COMPILER_COMMIT = "ef761e567dc94ee"
EXPECTED_XCODE_VERSION = "27.0"
EXPECTED_XCODE_BUILD = "27A5209h"
EXPECTED_MACOS_SDK_VERSION = "27.0"
EXPECTED_MACOS_SDK_BUILD = "26A5368f"
EXPECTED_ARCHITECTURE = "arm64"
SWIFT_BUILD_TRIPLE = "arm64-apple-macosx15.0"
DEPLOYMENT_TARGET = "15.0"
TARGET_SPEEDUP = 1.10
MINIMUM_SAMPLE_COUNT = 30
MINIMUM_SAMPLE_NANOSECONDS = 200_000_000
MAXIMUM_CALIBRATION_ROUNDS = 8
CONVERGENCE_WINDOW = 3
MAXIMUM_CONVERGENCE_ROUNDS = 10
CONVERGENCE_TOLERANCE = 0.05
MAXIMUM_LOAD_PER_LOGICAL_CPU = 0.25
QUIESCENCE_POLL_SECONDS = 5
DEFAULT_QUIESCENCE_TIMEOUT_SECONDS = 600
PARAMETER_SETS = (44, 65, 87)
WORKLOADS = tuple(
    (parameter_set, operation)
    for parameter_set in PARAMETER_SETS
    for operation in ("keygen", "sign", "verify")
)
INITIAL_ITERATIONS = {
    (44, "keygen"): 15_000,
    (44, "sign"): 7_500,
    (44, "verify"): 20_000,
    (65, "keygen"): 10_000,
    (65, "sign"): 5_000,
    (65, "verify"): 15_000,
    (87, "keygen"): 7_500,
    (87, "sign"): 3_500,
    (87, "verify"): 10_000,
}
PUBLIC_KEY_BYTES = {44: 1_312, 65: 1_952, 87: 2_592}
SIGNATURE_BYTES = {44: 2_420, 65: 3_309, 87: 4_627}
RESULT_PATTERN = re.compile(r"^RESULT,([0-9]+),([0-9]+)$")
FIXTURE_PATTERN = re.compile(r"^FIXTURE,([0-9a-f]+),([0-9a-f]+)$")
POWER_MODE_PATTERN = re.compile(r"(?:lowpowermode|powermode)\s+([0-9]+)")
BUILD_PROCESS_NAMES = frozenset(
    {
        "c++",
        "cc1",
        "cc",
        "clang",
        "clang++",
        "cmake",
        "ld",
        "ld64",
        "ninja",
        "swift",
        "swift-build",
        "swift-driver",
        "swift-frontend",
        "swiftc",
        "xcodebuild",
    }
)
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parents[1]


class BenchmarkError(RuntimeError):
    """A benchmark contract or execution failure."""


def utc_now() -> str:
    return datetime_module.datetime.now(datetime_module.timezone.utc).isoformat()


def utc_file_timestamp() -> str:
    return datetime_module.datetime.now(datetime_module.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


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
            "Build and compare Pure Swift and pinned BoringSSL ML-DSA workers "
            "with randomized paired samples."
        )
    )
    parser.add_argument(
        "--boringssl-source",
        required=True,
        type=Path,
        help="Path to the clean pinned official BoringSSL checkout.",
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        help="Fresh build root; defaults to a unique repository .build child.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Result JSON path; defaults to Benchmarks/MLDSA/Results.",
    )
    parser.add_argument(
        "--samples",
        type=parse_positive_integer,
        default=30,
        help="Even paired sample count of at least 30.",
    )
    parser.add_argument(
        "--bootstrap-resamples",
        type=parse_positive_integer,
        default=10_000,
        help="Paired bootstrap resample count.",
    )
    parser.add_argument("--seed", type=int, help="Reproducible random seed.")
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
        help="Require clean committed sources and build read-only snapshots.",
    )
    return parser


def sanitized_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    environment: dict[str, str] = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    for name in ("HOME", "LOGNAME", "TMPDIR", "USER"):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    if overrides is not None:
        environment.update(overrides)
    return environment


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=environment or sanitized_environment(),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise BenchmarkError(f"command failed to execute: {' '.join(command)}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise BenchmarkError(
            f"command failed with status {completed.returncode}: "
            f"{' '.join(command)}: {detail}"
        )
    return completed


def git_value(repository: Path, arguments: Sequence[str]) -> str:
    return run_command(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        cwd=repository,
        timeout_seconds=30,
    ).stdout.strip()


def optional_git_value(repository: Path, arguments: Sequence[str]) -> str | None:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        cwd=repository,
        env=sanitized_environment(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def git_metadata(repository: Path) -> dict[str, Any]:
    status = git_value(repository, ["status", "--porcelain=v1", "--untracked-files=all"])
    return {
        "path": str(repository.resolve()),
        "commit": git_value(repository, ["rev-parse", "HEAD"]),
        "origin": optional_git_value(repository, ["remote", "get-url", "origin"]),
        "statusPorcelain": status,
        "isClean": status == "",
    }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def executable_identity(invocation_path: Path) -> dict[str, Any]:
    resolved_path = invocation_path.resolve(strict=True)
    return {
        "invocationPath": str(invocation_path),
        "resolvedPath": str(resolved_path),
        "sha256": file_sha256(resolved_path),
        "sizeBytes": resolved_path.stat().st_size,
    }


def verify_executable_identities(
    identities: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    final: dict[str, dict[str, Any]] = {}
    for name, initial in identities.items():
        observed = executable_identity(Path(initial["invocationPath"]))
        if observed["resolvedPath"] != initial["resolvedPath"]:
            raise BenchmarkError(f"{name} invocation path changed target")
        if observed["sha256"] != initial["sha256"]:
            raise BenchmarkError(f"{name} executable changed during comparison")
        final[name] = observed
    return final


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(file_sha256(path)))
    return digest.hexdigest()


def make_snapshot(repository: Path, commit: str, destination: Path) -> dict[str, Any]:
    archive = destination.parent / f"{destination.name}.tar"
    run_command(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "archive",
            "--format=tar",
            "--output",
            str(archive),
            commit,
        ],
        cwd=repository,
        timeout_seconds=120,
    )
    destination.mkdir()
    run_command(
        ["/usr/bin/tar", "-xf", str(archive), "-C", str(destination)],
        cwd=destination.parent,
        timeout_seconds=120,
    )
    archive_digest = file_sha256(archive)
    for path in sorted(destination.rglob("*"), reverse=True):
        if path.is_symlink():
            raise BenchmarkError(f"formal source snapshot contains symlink: {path}")
        path.chmod(0o555 if path.is_dir() else 0o444)
    destination.chmod(0o555)
    archive.chmod(0o444)
    return {
        "commit": commit,
        "archivePath": str(archive),
        "archiveSHA256": archive_digest,
        "treeSHA256": tree_sha256(destination),
        "path": str(destination),
    }


def locate_single_executable(root: Path, name: str) -> Path:
    candidates = [
        path
        for path in root.rglob(name)
        if path.is_file() and os.access(path, os.X_OK)
    ]
    if len(candidates) != 1:
        raise BenchmarkError(
            f"expected one executable named {name} under {root}, found {len(candidates)}"
        )
    return candidates[0]


def resolve_xcrun_tool(name: str) -> Path:
    value = run_command(
        ["/usr/bin/xcrun", "--toolchain", EXPECTED_SWIFT_TOOLCHAIN, "--find", name],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=sanitized_environment({"TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN}),
    ).stdout.strip()
    path = Path(value)
    if not path.is_absolute():
        raise BenchmarkError(f"xcrun returned a relative path for {name}: {path}")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise BenchmarkError(f"xcrun did not resolve an executable {name}: {path}")
    return path


def collect_toolchain_metadata() -> dict[str, Any]:
    developer_directory = run_command(
        ["/usr/bin/xcode-select", "-p"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
    ).stdout.strip()
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": developer_directory,
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    tools = {
        name: str(resolve_xcrun_tool(name))
        for name in ("swift", "swiftc", "clang", "clang++", "lipo", "vtool", "nm", "otool")
    }
    tool_identities = {
        name: executable_identity(Path(path)) for name, path in tools.items()
    }
    swift_version = run_command(
        [tools["swift"], "--version"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip()
    if EXPECTED_SWIFT_COMPILER_COMMIT not in swift_version:
        raise BenchmarkError(
            f"Swift compiler commit mismatch: expected {EXPECTED_SWIFT_COMPILER_COMMIT}"
        )
    target_match = re.search(r"^Target:\s+(.+)$", swift_version, re.MULTILINE)
    if target_match is None or not target_match.group(1).startswith("arm64-apple-macosx"):
        raise BenchmarkError("Swift compiler default target is not arm64 macOS")
    sdk_path = run_command(
        ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip()
    sdk_version = run_command(
        ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip()
    sdk_build = run_command(
        ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip()
    xcode_version = run_command(
        ["/usr/bin/xcodebuild", "-version"],
        cwd=REPOSITORY_ROOT,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip()
    expected_xcode = f"Xcode {EXPECTED_XCODE_VERSION}\nBuild version {EXPECTED_XCODE_BUILD}"
    if xcode_version != expected_xcode:
        raise BenchmarkError(
            f"Xcode mismatch: expected {expected_xcode!r}, found {xcode_version!r}"
        )
    if sdk_version != EXPECTED_MACOS_SDK_VERSION or sdk_build != EXPECTED_MACOS_SDK_BUILD:
        raise BenchmarkError(
            "macOS SDK mismatch: "
            f"expected {EXPECTED_MACOS_SDK_VERSION}/{EXPECTED_MACOS_SDK_BUILD}, "
            f"found {sdk_version}/{sdk_build}"
        )
    if platform.machine() != EXPECTED_ARCHITECTURE:
        raise BenchmarkError(
            f"runner architecture must be {EXPECTED_ARCHITECTURE}, found {platform.machine()}"
        )
    return {
        "capturedAt": utc_now(),
        "toolchainIdentifier": EXPECTED_SWIFT_TOOLCHAIN,
        "swiftVersion": swift_version,
        "swiftDefaultTarget": target_match.group(1),
        "developerDirectory": developer_directory,
        "xcodeVersion": EXPECTED_XCODE_VERSION,
        "xcodeBuild": EXPECTED_XCODE_BUILD,
        "macOSSDKPath": sdk_path,
        "macOSSDKVersion": sdk_version,
        "macOSSDKBuild": sdk_build,
        "buildTriple": SWIFT_BUILD_TRIPLE,
        "tools": tools,
        "toolIdentities": tool_identities,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logicalCPUCount": os.cpu_count(),
        "pythonVersion": sys.version,
    }


def collect_macho_metadata(path: Path, toolchain: dict[str, Any]) -> dict[str, Any]:
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    architectures = run_command(
        [toolchain["tools"]["lipo"], "-archs", str(path)],
        cwd=path.parent,
        timeout_seconds=30,
        environment=environment,
    ).stdout.strip().split()
    build_version = run_command(
        [toolchain["tools"]["vtool"], "-show-build", str(path)],
        cwd=path.parent,
        timeout_seconds=30,
        environment=environment,
    ).stdout
    minimum_match = re.search(r"^\s*minos\s+(\S+)$", build_version, re.MULTILINE)
    sdk_match = re.search(r"^\s*sdk\s+(\S+)$", build_version, re.MULTILINE)
    platform_match = re.search(r"^\s*platform\s+(\S+)$", build_version, re.MULTILINE)
    if minimum_match is None or sdk_match is None or platform_match is None:
        raise BenchmarkError(f"could not parse Mach-O build metadata for {path}")
    if architectures != [EXPECTED_ARCHITECTURE]:
        raise BenchmarkError(f"worker architecture mismatch for {path}: {architectures}")
    if platform_match.group(1) != "MACOS":
        raise BenchmarkError(f"worker platform mismatch for {path}")
    if minimum_match.group(1) != DEPLOYMENT_TARGET:
        raise BenchmarkError(
            f"worker deployment target mismatch for {path}: {minimum_match.group(1)}"
        )
    if sdk_match.group(1) != EXPECTED_MACOS_SDK_VERSION:
        raise BenchmarkError(
            f"worker linked SDK mismatch for {path}: {sdk_match.group(1)}"
        )
    return {
        "architectures": architectures,
        "platform": platform_match.group(1),
        "minimumOSVersion": minimum_match.group(1),
        "linkedSDKVersion": sdk_match.group(1),
        "vtoolOutput": build_version,
    }


def optional_command(command: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            list(command),
            env=sanitized_environment(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def collect_quiescence() -> dict[str, Any]:
    logical_cpu_count = os.cpu_count()
    load_average = os.getloadavg()
    process_output = optional_command(["/bin/ps", "-axo", "comm="])
    active_build_processes: dict[str, int] | None = None
    if process_output is not None:
        active_build_processes = {}
        for line in process_output.splitlines():
            name = Path(line.strip()).name.strip("()")
            if name in BUILD_PROCESS_NAMES:
                active_build_processes[name] = active_build_processes.get(name, 0) + 1
    power_state = optional_command(["/usr/bin/pmset", "-g", "batt"])
    thermal_state = optional_command(["/usr/bin/pmset", "-g", "therm"])
    power_configuration = optional_command(["/usr/bin/pmset", "-g"])
    power_mode = None
    if power_configuration is not None:
        matches = POWER_MODE_PATTERN.findall(power_configuration)
        if matches:
            power_mode = int(matches[-1], 10)
    return {
        "observedAt": utc_now(),
        "logicalCPUCount": logical_cpu_count,
        "loadAverage": list(load_average),
        "oneMinuteLoadPerLogicalCPU": (
            load_average[0] / logical_cpu_count if logical_cpu_count else None
        ),
        "maximumLoadPerLogicalCPU": MAXIMUM_LOAD_PER_LOGICAL_CPU,
        "activeBuildProcesses": active_build_processes,
        "powerState": power_state,
        "powerMode": power_mode,
        "thermalState": thermal_state,
    }


def quiescence_reasons(observation: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    load = observation["oneMinuteLoadPerLogicalCPU"]
    if load is None or load > MAXIMUM_LOAD_PER_LOGICAL_CPU:
        reasons.append(f"load per logical CPU is not within {MAXIMUM_LOAD_PER_LOGICAL_CPU}")
    processes = observation["activeBuildProcesses"]
    if processes is None:
        reasons.append("build process observation is unavailable")
    elif processes:
        reasons.append(f"build processes are active: {processes}")
    if observation["powerState"] is None or "AC Power" not in observation["powerState"]:
        reasons.append("host is not verifiably drawing from AC power")
    if observation["powerMode"] != 0:
        reasons.append("power mode is unavailable or not the normal mode")
    thermal = observation["thermalState"]
    if thermal is None or (
        "No thermal warning level has been recorded" not in thermal
        or "No performance warning level has been recorded" not in thermal
    ):
        reasons.append("thermal or performance state is not clean")
    return reasons


def wait_for_quiescence(timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        observation = collect_quiescence()
        reasons = quiescence_reasons(observation)
        if not reasons:
            return observation
        if time.monotonic() >= deadline:
            raise BenchmarkError("host did not become quiescent: " + "; ".join(reasons))
        time.sleep(QUIESCENCE_POLL_SECONDS)


def code_blocks_containing(disassembly: str, token: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] | None = None
    for line in disassembly.splitlines():
        if line.startswith("_") and line.endswith(":"):
            if current is not None:
                blocks.append("\n".join(current))
            current = [line] if token in line else None
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append("\n".join(current))
    return blocks


def inspect_worker_codegen(
    swift_worker: Path,
    boringssl_worker: Path,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    swift_symbols = run_command(
        [toolchain["tools"]["nm"], "-nm", str(swift_worker)],
        cwd=swift_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    swift_disassembly = run_command(
        [toolchain["tools"]["otool"], "-tvV", str(swift_worker)],
        cwd=swift_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    required_swift_symbols = tuple(
        symbol
        for parameter_set in PARAMETER_SETS
        for symbol in (
            f"MLDSA{parameter_set}O7keyPair",
            f"MLDSA{parameter_set}O4sign",
            f"MLDSA{parameter_set}O6verify",
        )
    ) + ("MLDSACore", "KeccakX2Core")
    missing_swift = [value for value in required_swift_symbols if value not in swift_symbols]
    if missing_swift:
        raise BenchmarkError(f"Swift ML-DSA symbols are missing: {missing_swift}")
    mldsa_blocks = code_blocks_containing(swift_disassembly, "MLDSACore")
    mldsa_simd_multiply_count = sum(
        block.count("umull.2d") + block.count("umull2.2d")
        for block in mldsa_blocks
    )
    sha3_counts = {
        instruction: swift_disassembly.count(instruction)
        for instruction in ("eor3.16b", "rax1.2d", "xar.2d", "bcax.16b")
    }
    if not mldsa_blocks or mldsa_simd_multiply_count < 400:
        raise BenchmarkError(
            "Swift ML-DSA code generation lost its SIMD Montgomery arithmetic shape"
        )
    if any(count == 0 for count in sha3_counts.values()):
        raise BenchmarkError("Swift ML-DSA code generation lost ARM SHA3 instructions")

    boringssl_symbols = run_command(
        [toolchain["tools"]["nm"], "-nm", str(boringssl_worker)],
        cwd=boringssl_worker.parent,
        timeout_seconds=120,
        environment=environment,
    ).stdout
    required_boringssl_symbols = tuple(
        symbol
        for parameter_set in PARAMETER_SETS
        for symbol in (
            f"_MLDSA{parameter_set}_generate_key",
            f"_MLDSA{parameter_set}_sign",
            f"_MLDSA{parameter_set}_verify",
            f"BCM_mldsa{parameter_set}",
        )
    )
    missing_boringssl = [
        value for value in required_boringssl_symbols if value not in boringssl_symbols
    ]
    if missing_boringssl:
        raise BenchmarkError(f"BoringSSL ML-DSA symbols are missing: {missing_boringssl}")
    capability = run_command(
        [str(boringssl_worker), "--capabilities"],
        cwd=boringssl_worker.parent,
        timeout_seconds=30,
    )
    if capability.stdout != "CAPABILITY,boringssl_asm,1\n" or capability.stderr:
        raise BenchmarkError("BoringSSL did not confirm its assembly capability")
    return {
        "swift": {
            "symbolTableSHA256": hashlib.sha256(swift_symbols.encode()).hexdigest(),
            "disassemblySHA256": hashlib.sha256(swift_disassembly.encode()).hexdigest(),
            "mldsaSIMDMontgomeryInstructionCount": mldsa_simd_multiply_count,
            "armSHA3InstructionCounts": sha3_counts,
            "passed": True,
        },
        "boringSSL": {
            "symbolTableSHA256": hashlib.sha256(boringssl_symbols.encode()).hexdigest(),
            "assemblyCapabilityRecord": capability.stdout.strip(),
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
    swift_environment = sanitized_environment(
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
        "swift-ssl-mldsa-benchmark",
        "-v",
    ]
    swift_build = run_command(
        swift_command,
        cwd=swift_source,
        timeout_seconds=build_timeout_seconds,
        environment=swift_environment,
    )
    swift_worker = locate_single_executable(
        swift_scratch,
        "swift-ssl-mldsa-benchmark",
    )

    cmake = shutil.which("cmake", path=swift_environment["PATH"])
    ninja = shutil.which("ninja", path=swift_environment["PATH"])
    if cmake is None or ninja is None:
        raise BenchmarkError("cmake and ninja are required")
    boringssl_build_root = build_root / "boringssl-build"
    driver_source = swift_source / "Benchmarks/MLDSA/BoringSSLDriver"
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
    configure = run_command(
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
        "boringssl-mldsa-benchmark",
        "--",
        "-v",
    ]
    boringssl_build = run_command(
        build_command,
        cwd=build_root,
        timeout_seconds=build_timeout_seconds,
        environment=swift_environment,
    )
    boringssl_worker = locate_single_executable(
        boringssl_build_root,
        "boringssl-mldsa-benchmark",
    )

    swift_log = swift_build.stdout + "\n" + swift_build.stderr
    for module in ("SSLCore", "SSLCrypto", "SSL", "SSLMLDSABenchmark"):
        module_lines = [
            line
            for line in swift_log.splitlines()
            if f"-module-name {module}" in line
        ]
        if not module_lines:
            raise BenchmarkError(f"Swift build did not expose a compile command for {module}")
        if not any(
            " -O " in f" {line} "
            and f"-target {SWIFT_BUILD_TRIPLE}" in line
            and f"-sdk {toolchain['macOSSDKPath']}" in line
            for line in module_lines
        ):
            raise BenchmarkError(f"Swift build contract mismatch for {module}")
    forbidden_swift_flags = ("-Onone", "-sanitize=", "-profile-generate", "-coverage-prefix-map")
    present_swift_flags = [flag for flag in forbidden_swift_flags if flag in swift_log]
    if present_swift_flags:
        raise BenchmarkError(f"Swift build contains forbidden flags: {present_swift_flags}")

    compile_database_path = boringssl_build_root / "compile_commands.json"
    cmake_cache_path = boringssl_build_root / "CMakeCache.txt"
    if not compile_database_path.is_file() or not cmake_cache_path.is_file():
        raise BenchmarkError("BoringSSL build metadata is incomplete")
    compile_database = json.loads(compile_database_path.read_text(encoding="utf-8"))
    if not isinstance(compile_database, list):
        raise BenchmarkError("BoringSSL compile database root must be an array")
    compiled_files = {Path(entry["file"]).resolve() for entry in compile_database}
    required_boringssl_sources = {
        (driver_source / "MLDSABenchmark.cpp").resolve(),
        (boringssl_source / "crypto/mldsa/mldsa.cc").resolve(),
        (boringssl_source / "crypto/fipsmodule/bcm.cc").resolve(),
    }
    missing_sources = sorted(str(path) for path in required_boringssl_sources - compiled_files)
    if missing_sources:
        raise BenchmarkError(f"BoringSSL required sources were not compiled: {missing_sources}")
    for entry in compile_database:
        command = entry.get("command") or " ".join(entry.get("arguments", []))
        try:
            arguments = shlex.split(command)
        except ValueError as error:
            raise BenchmarkError("could not parse BoringSSL compile command") from error
        if "-O3" not in arguments or "-DNDEBUG" not in arguments:
            raise BenchmarkError(f"BoringSSL compile command is not Release: {entry['file']}")
        if any(
            argument.startswith(("-fsanitize", "-fprofile", "--config"))
            or argument in ("-DOPENSSL_NO_ASM", "-DOPENSSL_NO_ASM=1")
            for argument in arguments
        ):
            raise BenchmarkError(f"BoringSSL compile command violates the benchmark contract")
    cmake_cache = cmake_cache_path.read_text(encoding="utf-8")
    if "OPENSSL_NO_ASM:BOOL=OFF" not in cmake_cache:
        raise BenchmarkError("BoringSSL assembly is not enabled in CMake cache")

    worker_metadata = {
        "swift": {
            "path": str(swift_worker),
            "sha256": file_sha256(swift_worker),
            "sizeBytes": swift_worker.stat().st_size,
            "machO": collect_macho_metadata(swift_worker, toolchain),
        },
        "boringSSL": {
            "path": str(boringssl_worker),
            "sha256": file_sha256(boringssl_worker),
            "sizeBytes": boringssl_worker.stat().st_size,
            "machO": collect_macho_metadata(boringssl_worker, toolchain),
        },
    }
    code_generation = inspect_worker_codegen(swift_worker, boringssl_worker, toolchain)

    return swift_worker, boringssl_worker, {
        "swift": {
            "command": swift_command,
            "environment": swift_environment,
            "stdoutSHA256": hashlib.sha256(swift_build.stdout.encode()).hexdigest(),
            "stderr": swift_build.stderr,
            "contract": {
                "configuration": "release",
                "architecture": EXPECTED_ARCHITECTURE,
                "target": SWIFT_BUILD_TRIPLE,
                "sdk": toolchain["macOSSDKPath"],
                "validatedModules": [
                    "SSLCore",
                    "SSLCrypto",
                    "SSL",
                    "SSLMLDSABenchmark",
                ],
                "passed": True,
            },
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
            "sha256": file_sha256(compile_database_path),
            "entryCount": len(compile_database),
            "requiredSources": sorted(str(path) for path in required_boringssl_sources),
            "assemblyEnabled": True,
            "passed": True,
        },
        "workers": worker_metadata,
        "codeGeneration": code_generation,
    }


def parse_worker_result(stdout: str, stderr: str) -> dict[str, int]:
    if stderr != "":
        raise BenchmarkError(f"worker emitted stderr: {stderr.strip()}")
    lines = stdout.splitlines()
    if len(lines) != 1:
        raise BenchmarkError(f"worker emitted {len(lines)} stdout records")
    match = RESULT_PATTERN.fullmatch(lines[0])
    if match is None:
        raise BenchmarkError(f"malformed worker output: {lines[0]}")
    nanoseconds = int(match.group(1))
    if nanoseconds <= 0:
        raise BenchmarkError("worker reported a nonpositive duration")
    return {"nanoseconds": nanoseconds, "checksum": int(match.group(2))}


def invoke_worker(
    worker: Path,
    parameter_set: int,
    operation: str,
    iterations: int,
    warmup_iterations: int,
    timeout_seconds: int,
) -> dict[str, int]:
    completed = run_command(
        [
            str(worker),
            str(parameter_set),
            operation,
            str(iterations),
            str(warmup_iterations),
        ],
        cwd=worker.parent,
        timeout_seconds=timeout_seconds,
    )
    return parse_worker_result(completed.stdout, completed.stderr)


def invoke_validation(worker: Path, arguments: Sequence[str]) -> str:
    completed = run_command(
        [str(worker), *arguments],
        cwd=worker.parent,
        timeout_seconds=120,
    )
    if completed.stderr:
        raise BenchmarkError(f"validation worker emitted stderr: {completed.stderr.strip()}")
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise BenchmarkError(f"validation worker emitted {len(lines)} records")
    return lines[0]


def parse_fixture_record(record: str, parameter_set: int) -> tuple[str, str]:
    match = FIXTURE_PATTERN.fullmatch(record)
    if match is None:
        raise BenchmarkError("worker emitted a malformed interoperability fixture")
    if (
        len(match.group(1)) != PUBLIC_KEY_BYTES[parameter_set] * 2
        or len(match.group(2)) != SIGNATURE_BYTES[parameter_set] * 2
    ):
        raise BenchmarkError(
            f"worker emitted invalid ML-DSA-{parameter_set} fixture lengths"
        )
    return match.group(1), match.group(2)


def validate_parameter_interoperability(
    swift_worker: Path,
    boringssl_worker: Path,
    parameter_set: int,
) -> dict[str, Any]:
    seed = bytes((0x21 + 37 * index) & 0xFF for index in range(32)).hex()
    message = bytes((0x42 + 37 * index) & 0xFF for index in range(64)).hex()
    context = bytes((0x63 + 37 * index) & 0xFF for index in range(19)).hex()
    randomizer = bytes((0x84 + 37 * index) & 0xFF for index in range(32)).hex()

    swift_record = invoke_validation(
        swift_worker,
        ["--fixture", str(parameter_set), seed, message, context, randomizer],
    )
    swift_public, swift_signature = parse_fixture_record(swift_record, parameter_set)
    if invoke_validation(
        boringssl_worker,
        [
            "--validate",
            str(parameter_set),
            seed,
            swift_public,
            swift_signature,
            message,
            context,
        ],
    ) != "VALIDATED":
        raise BenchmarkError("BoringSSL did not validate the SSL signature")

    boring_record = invoke_validation(
        boringssl_worker,
        ["--fixture", str(parameter_set), seed, message, context],
    )
    boring_public, boring_signature = parse_fixture_record(boring_record, parameter_set)
    if invoke_validation(
        swift_worker,
        [
            "--validate",
            str(parameter_set),
            seed,
            boring_public,
            boring_signature,
            message,
            context,
        ],
    ) != "VALIDATED":
        raise BenchmarkError("SSL did not validate the BoringSSL signature")

    mutated = bytearray.fromhex(swift_signature)
    mutated[len(mutated) // 2] ^= 0x80
    mutated_hex = mutated.hex()
    swift_mutation = invoke_validation(
        swift_worker,
        ["--verify", str(parameter_set), swift_public, mutated_hex, message, context],
    )
    boring_mutation = invoke_validation(
        boringssl_worker,
        ["--verify", str(parameter_set), swift_public, mutated_hex, message, context],
    )
    if swift_mutation != "VERIFIED,0" or boring_mutation != "VERIFIED,0":
        raise BenchmarkError(
            f"a mutated ML-DSA-{parameter_set} signature was accepted"
        )

    return {
        "method": "deterministic seeded keys, bidirectional signature validation, and mutated-signature rejection",
        "seed": seed,
        "messageSHA256": hashlib.sha256(bytes.fromhex(message)).hexdigest(),
        "contextSHA256": hashlib.sha256(bytes.fromhex(context)).hexdigest(),
        "swiftFixtureSHA256": hashlib.sha256(swift_record.encode()).hexdigest(),
        "boringSSLFixtureSHA256": hashlib.sha256(boring_record.encode()).hexdigest(),
        "swiftToBoringSSL": "validated",
        "boringSSLToSwift": "validated",
        "mutatedSignature": "rejected by both",
        "passed": True,
    }


def validate_interoperability(
    swift_worker: Path,
    boringssl_worker: Path,
) -> dict[str, Any]:
    results = {
        str(parameter_set): validate_parameter_interoperability(
            swift_worker,
            boringssl_worker,
            parameter_set,
        )
        for parameter_set in PARAMETER_SETS
    }
    return {
        "parameterSets": results,
        "passed": all(result["passed"] for result in results.values()),
    }


def convergence_reached(values: Sequence[float]) -> bool:
    if len(values) < CONVERGENCE_WINDOW:
        return False
    window = values[-CONVERGENCE_WINDOW:]
    center = statistics.median(window)
    return all(abs(value - center) / center <= CONVERGENCE_TOLERANCE for value in window)


def converge(
    swift_worker: Path,
    boringssl_worker: Path,
    parameter_set: int,
    operation: str,
    iterations: int,
    timeout_seconds: int,
    quiescence_timeout_seconds: int,
    generator: random.Random,
) -> list[dict[str, Any]]:
    rounds: list[dict[str, Any]] = []
    swift_values: list[float] = []
    boringssl_values: list[float] = []
    for index in range(MAXIMUM_CONVERGENCE_ROUNDS):
        quiescence = wait_for_quiescence(quiescence_timeout_seconds)
        swift_first = bool(generator.randrange(2))
        if swift_first:
            swift = invoke_worker(
                swift_worker, parameter_set, operation, iterations, 1_000, timeout_seconds
            )
            boring = invoke_worker(
                boringssl_worker, parameter_set, operation, iterations, 1_000, timeout_seconds
            )
        else:
            boring = invoke_worker(
                boringssl_worker, parameter_set, operation, iterations, 1_000, timeout_seconds
            )
            swift = invoke_worker(
                swift_worker, parameter_set, operation, iterations, 1_000, timeout_seconds
            )
        swift_values.append(swift["nanoseconds"] / iterations)
        boringssl_values.append(boring["nanoseconds"] / iterations)
        rounds.append(
            {
                "index": index,
                "order": "swift-first" if swift_first else "boringssl-first",
                "swift": swift,
                "boringSSL": boring,
                "quiescence": quiescence,
            }
        )
        if convergence_reached(swift_values) and convergence_reached(boringssl_values):
            return rounds
    raise BenchmarkError(
        f"timing did not converge for ML-DSA-{parameter_set} {operation}"
    )


def calibrate(
    swift_worker: Path,
    boringssl_worker: Path,
    parameter_set: int,
    operation: str,
    timeout_seconds: int,
) -> tuple[int, list[dict[str, Any]]]:
    iterations = INITIAL_ITERATIONS[(parameter_set, operation)]
    pilots: list[dict[str, Any]] = []
    for _ in range(MAXIMUM_CALIBRATION_ROUNDS):
        swift = invoke_worker(
            swift_worker,
            parameter_set,
            operation,
            iterations,
            1_000,
            timeout_seconds,
        )
        boringssl = invoke_worker(
            boringssl_worker,
            parameter_set,
            operation,
            iterations,
            1_000,
            timeout_seconds,
        )
        pilots.append(
            {"iterations": iterations, "swift": swift, "boringSSL": boringssl}
        )
        fastest = min(swift["nanoseconds"], boringssl["nanoseconds"])
        if fastest >= MINIMUM_SAMPLE_NANOSECONDS:
            return iterations, pilots
        scale = max(2, (MINIMUM_SAMPLE_NANOSECONDS + fastest - 1) // fastest)
        iterations *= scale
    raise BenchmarkError(
        f"calibration did not reach {MINIMUM_SAMPLE_NANOSECONDS} ns for "
        f"ML-DSA-{parameter_set} {operation}"
    )


def balanced_orders(sample_count: int, generator: random.Random) -> list[str]:
    if sample_count % 2 != 0:
        raise BenchmarkError("sample count must be even")
    orders = ["swift-first"] * (sample_count // 2)
    orders += ["boringssl-first"] * (sample_count // 2)
    generator.shuffle(orders)
    return orders


def percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def bootstrap_median_interval(
    values: Sequence[float],
    resamples: int,
    generator: random.Random,
) -> tuple[float, float]:
    if not values:
        raise BenchmarkError("cannot bootstrap an empty sample")
    medians: list[float] = []
    for _ in range(resamples):
        sample = [values[generator.randrange(len(values))] for _ in values]
        medians.append(statistics.median(sample))
    return percentile(medians, 0.025), percentile(medians, 0.975)


def summarize_workload(
    samples: Sequence[dict[str, Any]],
    iterations: int,
    bootstrap_resamples: int,
    generator: random.Random,
) -> dict[str, Any]:
    swift_per_operation = [
        sample["swift"]["nanoseconds"] / iterations for sample in samples
    ]
    boringssl_per_operation = [
        sample["boringSSL"]["nanoseconds"] / iterations for sample in samples
    ]
    paired_speedups = [
        boring / swift
        for boring, swift in zip(boringssl_per_operation, swift_per_operation)
    ]
    lower, upper = bootstrap_median_interval(
        paired_speedups,
        bootstrap_resamples,
        generator,
    )
    median_speedup = statistics.median(paired_speedups)
    return {
        "iterationsPerSample": iterations,
        "swiftMedianNanosecondsPerOperation": statistics.median(swift_per_operation),
        "swiftP95NanosecondsPerOperation": percentile(swift_per_operation, 0.95),
        "boringSSLMedianNanosecondsPerOperation": statistics.median(
            boringssl_per_operation
        ),
        "boringSSLP95NanosecondsPerOperation": percentile(
            boringssl_per_operation, 0.95
        ),
        "medianPairedSpeedup": median_speedup,
        "speedupConfidenceInterval95": [lower, upper],
        "targetSpeedup": TARGET_SPEEDUP,
        "passed": lower >= TARGET_SPEEDUP,
        "samples": list(samples),
    }


def collect_environment() -> dict[str, Any]:
    return collect_toolchain_metadata()


def main() -> int:
    arguments = build_argument_parser().parse_args()
    if arguments.samples < MINIMUM_SAMPLE_COUNT or arguments.samples % 2 != 0:
        raise BenchmarkError("samples must be even and at least 30")
    if arguments.bootstrap_resamples < 1_000:
        raise BenchmarkError("bootstrap resamples must be at least 1000")

    boringssl_source = arguments.boringssl_source.resolve()
    swift_metadata = git_metadata(REPOSITORY_ROOT)
    boringssl_metadata = git_metadata(boringssl_source)
    if boringssl_metadata["commit"] != EXPECTED_BORINGSSL_COMMIT:
        raise BenchmarkError("BoringSSL commit does not match the pinned baseline")
    if not boringssl_metadata["isClean"]:
        raise BenchmarkError("BoringSSL checkout must be clean")
    normalized_origin = (boringssl_metadata["origin"] or "").removesuffix(".git")
    if normalized_origin != EXPECTED_BORINGSSL_ORIGIN:
        raise BenchmarkError(
            f"BoringSSL origin mismatch: expected {EXPECTED_BORINGSSL_ORIGIN}"
        )
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
    bootstrap_generator = random.Random(seed ^ 0xA5A5_6D6C_4B45_4D21)

    output = arguments.output
    if output is None:
        output = (
            SCRIPT_DIRECTORY
            / "Results"
            / f"{utc_file_timestamp()}-native-mldsa.json"
        )
    output = output.resolve()
    if output.exists():
        raise BenchmarkError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    build_root = arguments.build_root
    if build_root is None:
        parent = REPOSITORY_ROOT / ".build" / "benchmark-mldsa"
        parent.mkdir(parents=True, exist_ok=True)
        build_root = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    else:
        build_root = build_root.resolve()
        if build_root.exists():
            raise BenchmarkError(f"build root already exists: {build_root}")
        build_root.mkdir(parents=True)

    environment = collect_environment()
    swift_source = REPOSITORY_ROOT
    selected_boringssl_source = boringssl_source
    snapshots: dict[str, Any] | None = None
    if arguments.formal:
        snapshots_root = build_root / "sources"
        snapshots_root.mkdir()
        swift_source = snapshots_root / "swift-ssl"
        selected_boringssl_source = snapshots_root / "boringssl"
        snapshots = {
            "ssl": make_snapshot(
                REPOSITORY_ROOT,
                swift_metadata["commit"],
                swift_source,
            ),
            "boringSSL": make_snapshot(
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
    worker_metadata = build_evidence["workers"]
    post_build_quiescence = wait_for_quiescence(
        arguments.quiescence_timeout_seconds
    )
    interoperability = validate_interoperability(swift_worker, boringssl_worker)

    workload_order = list(WORKLOADS)
    generator.shuffle(workload_order)
    results: dict[str, Any] = {}
    for parameter_set, operation in workload_order:
        iterations, calibration = calibrate(
            swift_worker,
            boringssl_worker,
            parameter_set,
            operation,
            arguments.worker_timeout_seconds,
        )
        convergence = converge(
            swift_worker,
            boringssl_worker,
            parameter_set,
            operation,
            iterations,
            arguments.worker_timeout_seconds,
            arguments.quiescence_timeout_seconds,
            generator,
        )
        samples: list[dict[str, Any]] = []
        for index, order in enumerate(balanced_orders(arguments.samples, generator)):
            quiescence = wait_for_quiescence(
                arguments.quiescence_timeout_seconds
            )
            if order == "swift-first":
                swift = invoke_worker(
                    swift_worker,
                    parameter_set,
                    operation,
                    iterations,
                    1_000,
                    arguments.worker_timeout_seconds,
                )
                boringssl = invoke_worker(
                    boringssl_worker,
                    parameter_set,
                    operation,
                    iterations,
                    1_000,
                    arguments.worker_timeout_seconds,
                )
            else:
                boringssl = invoke_worker(
                    boringssl_worker,
                    parameter_set,
                    operation,
                    iterations,
                    1_000,
                    arguments.worker_timeout_seconds,
                )
                swift = invoke_worker(
                    swift_worker,
                    parameter_set,
                    operation,
                    iterations,
                    1_000,
                    arguments.worker_timeout_seconds,
                )
            samples.append(
                {
                    "index": index,
                    "order": order,
                    "swift": swift,
                    "boringSSL": boringssl,
                    "quiescence": quiescence,
                }
            )
        key = f"mldsa{parameter_set}-{operation}"
        results[key] = {
            "parameterSet": parameter_set,
            "operation": operation,
            "calibration": calibration,
            "convergence": convergence,
            **summarize_workload(
                samples,
                iterations,
                arguments.bootstrap_resamples,
                bootstrap_generator,
            ),
        }

    final_swift_metadata = git_metadata(REPOSITORY_ROOT)
    final_boringssl_metadata = git_metadata(boringssl_source)
    if final_swift_metadata != swift_metadata:
        raise BenchmarkError("SSL repository identity changed during comparison")
    if final_boringssl_metadata != boringssl_metadata:
        raise BenchmarkError("BoringSSL repository identity changed during comparison")
    if file_sha256(swift_worker) != worker_metadata["swift"]["sha256"]:
        raise BenchmarkError("Swift worker changed during comparison")
    if file_sha256(boringssl_worker) != worker_metadata["boringSSL"]["sha256"]:
        raise BenchmarkError("BoringSSL worker changed during comparison")
    final_tool_identities = verify_executable_identities(
        environment["toolIdentities"]
    )
    final_snapshot_evidence: dict[str, Any] | None = None
    if snapshots is not None:
        final_snapshot_evidence = {}
        for name, snapshot in snapshots.items():
            final_archive_hash = file_sha256(Path(snapshot["archivePath"]))
            final_tree_hash = tree_sha256(Path(snapshot["path"]))
            if final_archive_hash != snapshot["archiveSHA256"]:
                raise BenchmarkError(f"{name} source archive changed during comparison")
            if final_tree_hash != snapshot["treeSHA256"]:
                raise BenchmarkError(f"{name} source snapshot changed during comparison")
            final_snapshot_evidence[name] = {
                "archiveSHA256": final_archive_hash,
                "treeSHA256": final_tree_hash,
                "unchanged": True,
            }
    final_quiescence = wait_for_quiescence(arguments.quiescence_timeout_seconds)

    passed = all(result["passed"] for result in results.values())
    artifact = {
        "schemaVersion": 2,
        "classification": "formal" if arguments.formal else "exploratory",
        "valid": True,
        "targetSpeedup": TARGET_SPEEDUP,
        "passed": passed,
        "seed": seed,
        "sampleCount": arguments.samples,
        "bootstrapResamples": arguments.bootstrap_resamples,
        "environment": environment,
        "finalToolIdentities": final_tool_identities,
        "sources": {
            "ssl": swift_metadata,
            "boringSSL": boringssl_metadata,
            "snapshots": snapshots,
        },
        "buildRoot": str(build_root),
        "build": build_evidence,
        "workers": worker_metadata,
        "interoperability": interoperability,
        "memoryEvidence": {
            "publicSigningOutput": "caller-owned MutableSpan",
            "verificationInputs": "borrowed Span values",
            "privateKey": "noncopyable secret owner",
            "allocationCountMeasured": False,
            "logicalCopyCountMeasured": False,
            "releaseQualification": "separate instrumented artifact required",
        },
        "quiescence": {
            "postBuild": post_build_quiescence,
            "final": final_quiescence,
        },
        "finalSnapshotEvidence": final_snapshot_evidence,
        "workloadOrder": [f"mldsa{p}-{o}" for p, o in workload_order],
        "results": results,
        "completedAt": utc_now(),
    }
    temporary_output = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    if temporary_output.exists():
        raise BenchmarkError(f"temporary output already exists: {temporary_output}")
    temporary_output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    if output.exists():
        temporary_output.unlink()
        raise BenchmarkError(f"output already exists: {output}")
    os.rename(temporary_output, output)
    print(f"artifact: {output}")
    for key in sorted(results):
        result = results[key]
        interval = result["speedupConfidenceInterval95"]
        print(
            f"{key}: {result['medianPairedSpeedup']:.4f}x "
            f"(95% CI {interval[0]:.4f}x...{interval[1]:.4f}x)"
        )
    print("decision: pass" if passed else "decision: target not established")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"invalid comparison: {error}", file=sys.stderr)
        raise SystemExit(2)
