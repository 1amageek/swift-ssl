#!/usr/bin/env python3
"""Build and compare Pure Swift and BoringSSL SHA-256 implementations."""

from __future__ import annotations

import argparse
import datetime as datetime_module
import hashlib
import json
import math
import os
import platform
import random
import re
import secrets
import shlex
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


EXPECTED_BORINGSSL_COMMIT = "ae49d2681a56ca7b8609f6039a770fda2a8eb550"
ARTIFACT_SCHEMA_VERSION = 4
EXPECTED_BORINGSSL_ORIGIN = "https://boringssl.googlesource.com/boringssl"
EXPECTED_SWIFT_TOOLCHAIN = "org.swift.64202607231a"
EXPECTED_SWIFT_COMPILER_COMMIT = "ef761e567dc94ee"
EXPECTED_XCODE_VERSION = "27.0"
EXPECTED_XCODE_BUILD = "27A5209h"
EXPECTED_MACOS_SDK_VERSION = "27.0"
EXPECTED_MACOS_SDK_BUILD = "26A5368f"
EXPECTED_ARCHITECTURE = "arm64"
SWIFT_BUILD_TRIPLE = "arm64-apple-macosx15.0"
SWIFT_COMPILE_TARGET = SWIFT_BUILD_TRIPLE
SWIFT_BUILD_DIRECTORY_TRIPLE = "arm64-apple-macosx"
DEPLOYMENT_TARGET = "15.0"
HEADLINE_BYTE_COUNTS = (64, 1024, 16384)
INITIAL_ITERATIONS = {
    64: 250_000,
    1024: 50_000,
    16384: 5_000,
}
VALIDATION_ITERATION_COUNT = 256
MINIMUM_SAMPLE_COUNT = 30
MINIMUM_BOOTSTRAP_RESAMPLES = 1_000
MINIMUM_SAMPLE_NANOSECONDS = 250_000_000
MAXIMUM_CALIBRATION_ROUNDS = 8
MAXIMUM_ITERATIONS = 1_000_000_000
CONVERGENCE_WINDOW = 3
MAXIMUM_CONVERGENCE_ROUNDS = 10
CONVERGENCE_TOLERANCE = 0.05
MAXIMUM_LOAD_PER_LOGICAL_CPU = 0.25
QUIESCENCE_POLL_SECONDS = 5
DEFAULT_QUIESCENCE_TIMEOUT_SECONDS = 600
TARGET_SPEEDUP = 1.10
MINIMUM_BUILD_AVAILABLE_BYTES = 3 * 1024 * 1024 * 1024
MINIMUM_ARTIFACT_RESERVE_BYTES = 256 * 1024 * 1024
BUILD_PROCESS_EXACT_NAMES = frozenset(
    {
        "c++",
        "cc1",
        "cc",
        "clang",
        "clang++",
        "cmake",
        "cargo",
        "g++",
        "gcc",
        "gmake",
        "go",
        "ld",
        "lld",
        "make",
        "ninja",
        "rustc",
        "swift",
        "swift-build",
        "swift-driver",
        "swift-frontend",
        "swiftc",
        "wasm-ld",
        "xcodebuild",
    }
)
BUILD_PROCESS_PREFIXES = (
    "clang-",
    "gcc-",
    "g++-",
    "ld64",
    "swift-",
    "swiftc-",
)
BUILD_PROCESS_EXCLUDED_EXACT_NAMES = frozenset(
    {
        "swift-plugin-server",
    }
)
RESULT_PATTERN = re.compile(r"^RESULT,([0-9]+),([0-9]+),([0-9a-f]{64})$")
DIGEST_PATTERN = re.compile(r"^DIGEST,([0-9]+),([0-9a-f]{64})$")
BORINGSSL_CAPABILITY_PATTERN = re.compile(
    r"^CAPABILITY,boringssl_asm,([01])$"
)
POWER_MODE_PATTERN = re.compile(r"(?:lowpowermode|powermode)\s+([0-9]+)")
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parents[1]
INHERITED_ENVIRONMENT_NAMES = frozenset(
    {
        "HOME",
        "LOGNAME",
        "TMPDIR",
        "USER",
    }
)
FIXED_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
}
GIT_EXECUTABLE = "/usr/bin/git"
XCRUN_EXECUTABLE = "/usr/bin/xcrun"
XCODEBUILD_EXECUTABLE = "/usr/bin/xcodebuild"
XCODE_SELECT_EXECUTABLE = "/usr/bin/xcode-select"
TAR_EXECUTABLE = "/usr/bin/tar"
PS_EXECUTABLE = "/bin/ps"
PMSET_EXECUTABLE = "/usr/bin/pmset"
SYSCTL_EXECUTABLE = "/usr/sbin/sysctl"
SW_VERS_EXECUTABLE = "/usr/bin/sw_vers"
CMAKE_EXECUTABLE_CANDIDATES = (
    "/opt/homebrew/bin/cmake",
    "/usr/local/bin/cmake",
    "/usr/bin/cmake",
)
NINJA_EXECUTABLE_CANDIDATES = (
    "/opt/homebrew/bin/ninja",
    "/usr/local/bin/ninja",
    "/usr/bin/ninja",
)
LOOP_FORBIDDEN_SYMBOLS = (
    "swift_isUniquelyReferenced",
    "consumeAndCreateNew",
    "swift_alloc",
    "swift_retain",
    "swift_release",
    "memcpy",
    "memmove",
)


class BenchmarkError(RuntimeError):
    """A benchmark contract or execution failure."""


def sanitized_environment(
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in INHERITED_ENVIRONMENT_NAMES
    }
    environment.update(FIXED_ENVIRONMENT)
    if overrides is not None:
        environment.update(overrides)
    return environment


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


def parse_nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a nonnegative integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected a nonnegative integer")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build and compare the Pure Swift and pinned BoringSSL SHA-256 "
            "workers with a fixed workload matrix and paired samples."
        )
    )
    parser.add_argument(
        "--boringssl-source",
        required=True,
        type=Path,
        help="Path to the clean checkout of the pinned official BoringSSL commit.",
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        help=(
            "Path for fresh runner-owned builds. The path must not exist. "
            "Defaults to a unique directory under the repository .build."
        ),
    )
    parser.add_argument(
        "--samples",
        type=parse_positive_integer,
        default=30,
        help=(
            "Paired samples per workload; must be even and at least 30 "
            "(default: 30)."
        ),
    )
    parser.add_argument(
        "--bootstrap-resamples",
        type=parse_positive_integer,
        default=10_000,
        help="Paired bootstrap resamples; must be at least 1000 (default: 10000).",
    )
    parser.add_argument(
        "--seed",
        type=parse_nonnegative_integer,
        help="Seed for workload order, pair order, and bootstrap reproducibility.",
    )
    parser.add_argument(
        "--worker-timeout-seconds",
        type=parse_positive_integer,
        default=120,
        help="Timeout for one worker invocation (default: 120).",
    )
    parser.add_argument(
        "--build-timeout-seconds",
        type=parse_positive_integer,
        default=1800,
        help="Timeout for each build command (default: 1800).",
    )
    parser.add_argument(
        "--quiescence-timeout-seconds",
        type=parse_positive_integer,
        default=DEFAULT_QUIESCENCE_TIMEOUT_SECONDS,
        help=(
            "Maximum post-build cooling wait for every timing run "
            f"(default: {DEFAULT_QUIESCENCE_TIMEOUT_SECONDS})."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Raw JSON path. Defaults to a unique file under "
            "Benchmarks/SHA256/Results."
        ),
    )
    parser.add_argument(
        "--formal",
        action="store_true",
        help=(
            "Require committed clean sources, the pinned toolchain, fresh builds, "
            "and all environmental gates. Other runs are exploratory."
        ),
    )
    return parser


def run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 30,
    environment: dict[str, str] | None = None,
    executable_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    selected_environment = (
        environment if environment is not None else sanitized_environment()
    )
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=selected_environment,
            executable=executable_path,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as error:
        raise BenchmarkError(f"command not found: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise BenchmarkError(
            f"command timed out after {timeout_seconds} seconds: {' '.join(command)}"
        ) from error

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise BenchmarkError(
            f"command failed with status {completed.returncode}: "
            f"{' '.join(command)}: {detail}"
        )
    return completed


def optional_command(command: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            list(command),
            env=sanitized_environment(),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def run_command_to_file(
    command: Sequence[str],
    *,
    cwd: Path,
    output_path: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    environment = sanitized_environment()
    try:
        with output_path.open("xb") as output:
            completed = subprocess.run(
                list(command),
                cwd=cwd,
                env=environment,
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
    except FileNotFoundError as error:
        raise BenchmarkError(f"command not found: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        if output_path.exists():
            output_path.unlink()
        raise BenchmarkError(
            f"command timed out after {timeout_seconds} seconds: "
            f"{' '.join(command)}"
        ) from error

    stderr = completed.stderr.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        if output_path.exists():
            output_path.unlink()
        raise BenchmarkError(
            f"command failed with status {completed.returncode}: "
            f"{' '.join(command)}: {stderr.strip()}"
        )
    return {
        "command": list(command),
        "cwd": str(cwd.resolve()),
        "environment": environment,
        "returnCode": completed.returncode,
        "stderr": stderr,
    }


def command_evidence(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    completed: subprocess.CompletedProcess[str],
    executable_path: str | None = None,
) -> dict[str, Any]:
    return {
        "command": list(command),
        "resolvedExecutablePath": executable_path or command[0],
        "cwd": str(cwd.resolve()),
        "environment": environment,
        "returnCode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def git_value(repository: Path, arguments: Sequence[str]) -> str | None:
    return optional_command(
        [GIT_EXECUTABLE, "-C", str(repository), *arguments]
    )


def git_metadata(repository: Path) -> dict[str, Any]:
    status = git_value(
        repository,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    return {
        "path": str(repository.resolve()),
        "commit": git_value(repository, ["rev-parse", "HEAD"]),
        "origin": git_value(repository, ["remote", "get-url", "origin"]),
        "statusPorcelain": status,
        "isClean": status == "",
    }


def normalize_boringssl_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    return origin.removesuffix("/").removesuffix(".git")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def executable_metadata(path: Path) -> dict[str, Any]:
    invocation_path = path.expanduser().absolute()
    resolved = invocation_path.resolve()
    if not resolved.is_file():
        raise BenchmarkError(f"executable does not exist: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"path is not executable: {resolved}")
    stat = resolved.stat()
    return {
        "path": str(resolved),
        "invocationPath": str(invocation_path),
        "sha256": file_sha256(resolved),
        "sizeBytes": stat.st_size,
        "modifiedTimeNanoseconds": stat.st_mtime_ns,
    }


def resolve_executable(
    *,
    label: str,
    candidates: Sequence[str],
) -> dict[str, Any]:
    failures: list[str] = []
    for candidate in candidates:
        candidate_path = Path(candidate)
        try:
            resolved = candidate_path.resolve(strict=True)
        except OSError as error:
            failures.append(f"{candidate}: {error}")
            continue
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            failures.append(f"{candidate}: not an executable file")
            continue
        return executable_metadata(resolved)
    raise BenchmarkError(
        f"could not resolve trusted {label} executable: "
        + "; ".join(failures)
    )


def verify_executable_metadata_unchanged(
    executables: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for label, initial in executables.items():
        invocation_path = Path(initial["invocationPath"])
        try:
            resolved_invocation = invocation_path.resolve(strict=True)
        except OSError as error:
            raise BenchmarkError(
                f"{label} invocation path could not be resolved at end"
            ) from error
        if str(resolved_invocation) != initial["path"]:
            raise BenchmarkError(
                f"{label} invocation path changed target during benchmark: "
                f"expected {initial['path']}, found {resolved_invocation}"
            )
        final = executable_metadata(invocation_path)
        if final["sha256"] != initial["sha256"]:
            raise BenchmarkError(f"{label} executable changed during benchmark")
        results[label] = final
    return results


def collect_macho_metadata(
    path: Path,
    *,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    architectures = run_command(
        [toolchain["lipo"]["invocationPath"], "-archs", str(path)],
        environment=environment,
        executable_path=toolchain["lipo"]["path"],
    ).stdout.strip().split()
    build_version = run_command(
        [toolchain["vtool"]["invocationPath"], "-show-build", str(path)],
        environment=environment,
        executable_path=toolchain["vtool"]["path"],
    ).stdout
    minimum_match = re.search(r"^\s*minos\s+(\S+)$", build_version, re.MULTILINE)
    sdk_match = re.search(r"^\s*sdk\s+(\S+)$", build_version, re.MULTILINE)
    platform_match = re.search(
        r"^\s*platform\s+(\S+)$",
        build_version,
        re.MULTILINE,
    )
    if minimum_match is None or sdk_match is None or platform_match is None:
        raise BenchmarkError(f"could not parse Mach-O build metadata for {path}")
    if architectures != [EXPECTED_ARCHITECTURE]:
        raise BenchmarkError(
            f"worker architecture mismatch for {path}: {architectures}"
        )
    if platform_match.group(1) != "MACOS":
        raise BenchmarkError(
            f"worker platform mismatch for {path}: {platform_match.group(1)}"
        )
    if minimum_match.group(1) != DEPLOYMENT_TARGET:
        raise BenchmarkError(
            f"worker deployment target mismatch for {path}: "
            f"expected {DEPLOYMENT_TARGET}, found {minimum_match.group(1)}"
        )
    if sdk_match.group(1) != EXPECTED_MACOS_SDK_VERSION:
        raise BenchmarkError(
            f"worker linked SDK mismatch for {path}: "
            f"expected {EXPECTED_MACOS_SDK_VERSION}, "
            f"found {sdk_match.group(1)}"
        )
    return {
        "architectures": architectures,
        "platform": platform_match.group(1),
        "minimumOSVersion": minimum_match.group(1),
        "linkedSDKVersion": sdk_match.group(1),
        "vtoolOutput": build_version,
    }


def require_swift_build_contract(
    *,
    completed: subprocess.CompletedProcess[str],
    toolchain: dict[str, Any],
    swift_source: Path,
    swift_scratch: Path,
) -> dict[str, Any]:
    verbose_log = completed.stdout + "\n" + completed.stderr
    command_marker = "builtin-SwiftDriver -- "
    commands_by_module: dict[str, list[tuple[str, ...]]] = {}
    for line in verbose_log.splitlines():
        if command_marker in line:
            command_text = line.split(command_marker, 1)[1]
        elif " -module-name " in line and "swiftc" in line:
            command_text = line
        else:
            continue
        try:
            arguments = shlex.split(command_text)
        except ValueError as error:
            raise BenchmarkError(
                "could not parse a Swift driver command"
            ) from error
        if "-module-name" not in arguments:
            continue
        module_index = arguments.index("-module-name")
        if module_index + 1 >= len(arguments):
            raise BenchmarkError("Swift driver command has no module name")
        module_name = arguments[module_index + 1]
        commands_by_module.setdefault(module_name, []).append(tuple(arguments))

    required_modules = (
        "SSLCore",
        "SSLCrypto",
        "SSLSHA256Benchmark",
    )
    forbidden_flags = (
        "-Onone",
        "-Osize",
        "-Ounchecked",
        "-coverage",
        "-profile",
        "-sanitize",
    )
    swift_source_root = swift_source.resolve()
    swift_scratch_root = swift_scratch.resolve()
    module_source_directories = {
        "SSLCore": swift_source_root / "Sources/SSLCore",
        "SSLCrypto": swift_source_root / "Sources/SSLCrypto",
        "SSLSHA256Benchmark": (
            swift_source_root / "Benchmarks/SHA256/SwiftWorker"
        ),
    }
    validated_commands: dict[str, list[list[str]]] = {}
    validated_source_lists: dict[str, dict[str, Any]] = {}
    logical_cpu_count = os.cpu_count()
    if logical_cpu_count is None or logical_cpu_count <= 0:
        raise BenchmarkError(
            "could not determine the logical CPU count for the Swift "
            "compile contract"
        )
    release_root = (
        swift_scratch_root
        / SWIFT_BUILD_DIRECTORY_TRIPLE
        / "release"
    )
    modules_root = release_root / "Modules"
    compiler_usr_root = Path(toolchain["swiftCompiler"]).resolve().parents[1]
    testing_library_root = (
        compiler_usr_root / "lib/swift/macosx/testing"
    )
    testing_plugin_root = (
        compiler_usr_root / "lib/swift/host/plugins/testing"
    )
    sdk_path = Path(toolchain["macOSSDKPath"]).resolve()
    platform_developer_root = sdk_path.parents[1]
    platform_framework_root = (
        platform_developer_root / "Library/Frameworks"
    )
    platform_library_root = platform_developer_root / "usr/lib"
    enabled_features = {
        "SSLCore": (
            "NonescapableTypes",
            "LifetimeDependence",
            "InoutLifetimeDependence",
            "LifetimeDependenceMutableAccessors",
            "Lifetimes",
            "Extern",
            "Volatile",
        ),
        "SSLCrypto": (
            "NonescapableTypes",
            "LifetimeDependence",
            "InoutLifetimeDependence",
            "LifetimeDependenceMutableAccessors",
            "Lifetimes",
            "Extern",
            "BuiltinModule",
        ),
        "SSLSHA256Benchmark": (
            "NonescapableTypes",
            "LifetimeDependence",
            "InoutLifetimeDependence",
            "LifetimeDependenceMutableAccessors",
            "Lifetimes",
            "Extern",
        ),
    }
    for module_name in required_modules:
        module_commands = sorted(set(commands_by_module.get(module_name, [])))
        if len(module_commands) != 1:
            raise BenchmarkError(
                f"Swift build log must contain exactly one whole-module "
                f"compile command for {module_name}; found "
                f"{len(module_commands)}"
            )
        for arguments_tuple in module_commands:
            arguments = list(arguments_tuple)
            compiler = str(Path(arguments[0]).resolve())
            if compiler != toolchain["swiftCompiler"]:
                raise BenchmarkError(
                    f"{module_name} used an unexpected Swift compiler: "
                    f"{compiler}"
                )
            if arguments.count("-O") != 1:
                raise BenchmarkError(
                    f"{module_name} must use exactly one -O flag"
                )
            if "-whole-module-optimization" not in arguments:
                raise BenchmarkError(
                    f"{module_name} is missing whole-module optimization"
                )
            for option, expected in (
                ("-target", SWIFT_COMPILE_TARGET),
                ("-sdk", toolchain["macOSSDKPath"]),
            ):
                option_indices = [
                    index
                    for index, argument in enumerate(arguments)
                    if argument == option
                ]
                values = [
                    arguments[index + 1]
                    for index in option_indices
                    if index + 1 < len(arguments)
                ]
                if values != [expected]:
                    raise BenchmarkError(
                        f"{module_name} has invalid {option} values: {values}"
                    )
            present_forbidden = [
                flag
                for flag in forbidden_flags
                if any(
                    argument == flag or argument.startswith(flag)
                    for argument in arguments
                )
            ]
            if present_forbidden:
                raise BenchmarkError(
                    f"{module_name} used forbidden Swift flags: "
                    + ", ".join(present_forbidden)
                )
            response_arguments = [
                argument for argument in arguments if argument.startswith("@")
            ]
            if len(response_arguments) != 1:
                raise BenchmarkError(
                    f"{module_name} must use exactly one verified source-list "
                    f"response file; found {response_arguments}"
                )
            response_path = Path(response_arguments[0][1:]).resolve()
            try:
                response_path.relative_to(swift_scratch_root)
            except ValueError as error:
                raise BenchmarkError(
                    f"{module_name} response file is outside the fresh "
                    f"Swift scratch directory: {response_path}"
                ) from error
            expected_response_path = (
                release_root / f"{module_name}.build/sources"
            )
            if response_path != expected_response_path:
                raise BenchmarkError(
                    f"{module_name} used an unexpected response file: "
                    f"{response_path}"
                )
            if not response_path.is_file():
                raise BenchmarkError(
                    f"{module_name} source-list response file does not exist: "
                    f"{response_path}"
                )
            try:
                source_tokens = shlex.split(
                    response_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeError, ValueError) as error:
                raise BenchmarkError(
                    f"{module_name} source-list response file is invalid"
                ) from error
            if not source_tokens or any(
                token.startswith("-") for token in source_tokens
            ):
                raise BenchmarkError(
                    f"{module_name} source-list response file contains "
                    "non-source arguments"
                )
            response_sources = [Path(token).resolve() for token in source_tokens]
            if any(path.suffix != ".swift" for path in response_sources):
                raise BenchmarkError(
                    f"{module_name} source-list response file contains "
                    "a non-Swift input"
                )
            expected_sources = sorted(
                path.resolve()
                for path in module_source_directories[module_name].rglob(
                    "*.swift"
                )
            )
            if (
                len(response_sources) != len(set(response_sources))
                or sorted(response_sources) != expected_sources
            ):
                raise BenchmarkError(
                    f"{module_name} source-list response file does not match "
                    "the trusted module source set"
                )
            direct_sources = [
                argument
                for argument in arguments
                if argument.endswith(".swift")
            ]
            if direct_sources:
                raise BenchmarkError(
                    f"{module_name} used unvalidated direct Swift sources: "
                    + ", ".join(direct_sources)
                )
            evidence = {
                "path": str(response_path),
                "sha256": file_sha256(response_path),
                "sources": [str(path) for path in response_sources],
            }
            previous_evidence = validated_source_lists.get(module_name)
            if previous_evidence is not None and previous_evidence != evidence:
                raise BenchmarkError(
                    f"{module_name} used inconsistent source lists"
                )
            validated_source_lists[module_name] = evidence
            module_build_root = release_root / f"{module_name}.build"
            expected_arguments = [
                arguments[0],
                "-module-name",
                module_name,
                "-emit-dependencies",
                "-emit-module",
                "-emit-module-path",
                str(modules_root / f"{module_name}.swiftmodule"),
                "-output-file-map",
                str(module_build_root / "output-file-map.json"),
            ]
            if module_name != "SSLSHA256Benchmark":
                expected_arguments.append("-parse-as-library")
            expected_arguments.extend(
                [
                    "-whole-module-optimization",
                    "-num-threads",
                    str(logical_cpu_count),
                    "-c",
                    f"@{response_path}",
                    "-I",
                    str(modules_root),
                    "-target",
                    SWIFT_COMPILE_TARGET,
                    "-v",
                    "-whole-module-optimization",
                    "-num-threads",
                    str(logical_cpu_count),
                    "-serialize-diagnostics",
                    "-O",
                    "-j2",
                    "-DSWIFT_PACKAGE",
                    "-DSWIFT_MODULE_RESOURCE_BUNDLE_UNAVAILABLE",
                    "-module-cache-path",
                    str(release_root / "ModuleCache"),
                    "-parseable-output",
                ]
            )
            if module_name == "SSLSHA256Benchmark":
                expected_arguments.extend(
                    [
                        "-Xfrontend",
                        "-entry-point-function-name",
                        "-Xfrontend",
                        "SSLSHA256Benchmark_main",
                        "-parse-as-library",
                    ]
                )
            else:
                expected_arguments.extend(
                    [
                        "-parse-as-library",
                        "-emit-objc-header",
                        "-emit-objc-header-path",
                        str(
                            module_build_root
                            / f"include/{module_name}-Swift.h"
                        ),
                    ]
                )
            expected_arguments.extend(["-swift-version", "6"])
            for feature in enabled_features[module_name]:
                expected_arguments.extend(
                    ["-enable-experimental-feature", feature]
                )
            expected_arguments.extend(
                [
                    "-I",
                    str(testing_library_root),
                    "-L",
                    str(testing_library_root),
                    "-plugin-path",
                    str(testing_plugin_root),
                    "-sdk",
                    toolchain["macOSSDKPath"],
                    "-F",
                    str(platform_framework_root),
                    "-I",
                    str(platform_library_root),
                    "-L",
                    str(platform_library_root),
                    "-g",
                    "-Xcc",
                    "-isysroot",
                    "-Xcc",
                    toolchain["macOSSDKPath"],
                    "-Xcc",
                    "-F",
                    "-Xcc",
                    str(platform_framework_root),
                    "-Xcc",
                    "-fPIC",
                    "-Xcc",
                    "-g",
                    "-package-name",
                    "swift_ssl",
                ]
            )
            if arguments != expected_arguments:
                raise BenchmarkError(
                    f"{module_name} compile command does not match the "
                    "pinned Swift command shape"
                )
        validated_commands[module_name] = [
            list(arguments) for arguments in module_commands
        ]
    return {
        "requestedTargetTriple": SWIFT_BUILD_TRIPLE,
        "compilerTarget": SWIFT_COMPILE_TARGET,
        "sdkPath": toolchain["macOSSDKPath"],
        "configuration": "release",
        "optimizationFlagObserved": "-O",
        "wholeModuleOptimizationRequired": True,
        "validatedModules": validated_commands,
        "validatedSourceLists": validated_source_lists,
        "exactCommandShapeRequired": True,
        "trustedSwiftSourceRoot": str(swift_source_root),
        "freshSwiftScratchRoot": str(swift_scratch_root),
        "forbiddenFlagsAbsent": list(forbidden_flags),
    }


def require_boringssl_build_contract(
    *,
    compile_database: list[dict[str, Any]],
    cmake_cache: str,
    toolchain: dict[str, Any],
    swift_source: Path,
    boringssl_source: Path,
    boringssl_build: Path,
) -> dict[str, Any]:
    required_cache_entries = {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_ASM_FLAGS_RELEASE": "-O3 -DNDEBUG",
        "CMAKE_CXX_FLAGS_RELEASE": "-O3 -DNDEBUG",
        "CMAKE_C_FLAGS_RELEASE": "-O3 -DNDEBUG",
        "CMAKE_ASM_COMPILER": toolchain["clangCompiler"],
        "CMAKE_C_COMPILER": toolchain["clangCompiler"],
        "CMAKE_CXX_COMPILER": toolchain["clangxxCompiler"],
        "CMAKE_CXX_COMPILER_ARG1": "--driver-mode=g++",
        "CMAKE_MAKE_PROGRAM": toolchain["ninja"]["path"],
        "CMAKE_OSX_ARCHITECTURES": EXPECTED_ARCHITECTURE,
        "CMAKE_OSX_DEPLOYMENT_TARGET": DEPLOYMENT_TARGET,
        "CMAKE_OSX_SYSROOT": toolchain["macOSSDKPath"],
        "CFI": "OFF",
        "MSAN": "OFF",
        "OPENSSL_NO_ASM": "OFF",
    }
    parsed_cache: dict[str, str] = {}
    for line in cmake_cache.splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        typed_key, value = line.split("=", 1)
        key = typed_key.split(":", 1)[0]
        parsed_cache[key] = value
    mismatches = {
        key: {
            "expected": expected,
            "actual": parsed_cache.get(key),
        }
        for key, expected in required_cache_entries.items()
        if parsed_cache.get(key) != expected
    }
    if mismatches:
        raise BenchmarkError(
            "BoringSSL CMake cache does not satisfy the build contract: "
            + json.dumps(mismatches, sort_keys=True)
        )

    swift_source_root = swift_source.resolve()
    boringssl_source_root = boringssl_source.resolve()
    boringssl_build_root = boringssl_build.resolve()
    expected_driver_source = (
        swift_source_root
        / "Benchmarks/SHA256/BoringSSLDriver/SHA256Benchmark.cpp"
    )
    expected_include_flag = f"-I{boringssl_source_root / 'include'}"
    compile_arguments: list[
        tuple[dict[str, Any], list[str], Path]
    ] = []
    for entry in compile_database:
        arguments_value = entry.get("arguments")
        command_value = entry.get("command")
        if isinstance(arguments_value, list) and all(
            isinstance(argument, str) for argument in arguments_value
        ):
            arguments = list(arguments_value)
        elif isinstance(command_value, str):
            try:
                arguments = shlex.split(command_value)
            except ValueError as error:
                raise BenchmarkError(
                    "could not parse a BoringSSL compile command"
                ) from error
        else:
            raise BenchmarkError(
                "BoringSSL compile database contains an invalid command"
            )
        if not arguments:
            raise BenchmarkError(
                "BoringSSL compile database contains an empty command"
            )
        response_files = [
            argument for argument in arguments if argument.startswith("@")
        ]
        if response_files:
            raise BenchmarkError(
                "BoringSSL compile command used forbidden response files: "
                + ", ".join(response_files)
            )
        source_value = entry.get("file")
        if not isinstance(source_value, str) or not source_value:
            raise BenchmarkError(
                "BoringSSL compile database entry has no source path"
            )
        directory_value = entry.get("directory")
        if not isinstance(directory_value, str) or not directory_value:
            raise BenchmarkError(
                "BoringSSL compile database entry has no build directory"
            )
        compile_directory = Path(directory_value).resolve()
        if compile_directory != boringssl_build_root:
            raise BenchmarkError(
                "BoringSSL compile command used an unexpected build "
                f"directory: {compile_directory}"
            )
        source_path = Path(source_value)
        if not source_path.is_absolute():
            source_path = compile_directory / source_path
        resolved_source = source_path.resolve()
        if resolved_source != expected_driver_source:
            try:
                resolved_source.relative_to(boringssl_source_root)
            except ValueError as error:
                raise BenchmarkError(
                    "BoringSSL compile source is outside the trusted source "
                    f"roots: {resolved_source}"
                ) from error
        compile_arguments.append((entry, arguments, resolved_source))

    driver_entries = [
        (entry, arguments, resolved_source)
        for entry, arguments, resolved_source in compile_arguments
        if resolved_source == expected_driver_source
    ]
    if len(driver_entries) != 1:
        raise BenchmarkError(
            "BoringSSL compile database must contain exactly one benchmark driver"
        )
    required_sources = {
        "Benchmarks/SHA256/BoringSSLDriver/SHA256Benchmark.cpp": (
            expected_driver_source
        ),
        "crypto/cpu_aarch64_apple.cc": (
            boringssl_source_root / "crypto/cpu_aarch64_apple.cc"
        ),
        "crypto/fipsmodule/bcm.cc": (
            boringssl_source_root / "crypto/fipsmodule/bcm.cc"
        ),
        "crypto/sha/sha256.cc": (
            boringssl_source_root / "crypto/sha/sha256.cc"
        ),
        "gen/bcm/sha256-armv8-apple.S": (
            boringssl_source_root / "gen/bcm/sha256-armv8-apple.S"
        ),
    }
    validated_source_entries: dict[str, str] = {}
    for relative_source, expected_source in required_sources.items():
        matching_sources = [
            str(resolved_source)
            for _, _, resolved_source in compile_arguments
            if resolved_source == expected_source
        ]
        if len(matching_sources) != 1:
            raise BenchmarkError(
                "BoringSSL compile database must contain exactly one "
                f"{expected_source} entry; found {len(matching_sources)}"
            )
        validated_source_entries[relative_source] = matching_sources[0]
    forbidden_flags = (
        "-O0",
        "--coverage",
        "-fcoverage",
        "-fprofile",
        "-fsanitize",
        "-ftest-coverage",
    )
    forbidden_escape_flags = (
        "--config",
        "-Xassembler",
        "-Xclang",
        "-Xlinker",
        "-mllvm",
        "-Wl,",
        "-Wp,",
    )
    forbidden_header_path_flags = (
        "-F",
        "-iframework",
        "-imacros",
        "-include",
        "-iquote",
        "-isystem",
        "-ivfsoverlay",
        "-fmodule-map-file",
    )
    allowed_fixed_arguments = frozenset(
        {
            "--driver-mode=g++",
            "-DBORINGSSL_IMPLEMENTATION",
            "-DNDEBUG",
            "-O3",
            "-Wa,--noexecstack",
            "-Wall",
            "-Wctad-maybe-unsupported",
            "-Werror",
            "-Wextra-semi",
            "-Wformat=2",
            "-Wframe-larger-than=25344",
            "-Wheader-hygiene",
            "-Wimplicit-fallthrough",
            "-Wmissing-field-initializers",
            "-Wmissing-prototypes",
            "-Wnewline-eof",
            "-Wshadow",
            "-Wsign-compare",
            "-Wstring-concatenation",
            "-Wtype-limits",
            "-Wvla",
            "-Wwrite-strings",
            "-fcolor-diagnostics",
            "-fno-aligned-new",
            "-fno-common",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-strict-aliasing",
            "-fvisibility=hidden",
            "-ggdb",
            "-std=gnu++17",
        }
    )
    forbidden_assembly_definitions = (
        "-DOPENSSL_NO_ASM",
        "-DBORINGSSL_NO_ASM",
        "-DOPENSSL_ASM_INCOMPATIBLE",
    )
    allowed_compilers = {
        str(Path(toolchain["clangCompiler"]).resolve()),
        str(Path(toolchain["clangxxCompiler"]).resolve()),
    }
    validated_object_outputs: list[str] = []
    validated_compile_outputs: list[dict[str, str]] = []
    for entry, arguments, resolved_source in compile_arguments:
        source = str(resolved_source)
        compiler = str(Path(arguments[0]).resolve())
        if compiler not in allowed_compilers:
            raise BenchmarkError(
                f"BoringSSL compile command used an unexpected compiler for "
                f"{source}: {compiler}"
            )
        optimization_flags = [
            argument
            for argument in arguments
            if argument == "-O"
            or re.fullmatch(
                r"-O(?:[0-9]+|s|z|g|fast)",
                argument,
            )
            is not None
        ]
        if optimization_flags != ["-O3"]:
            raise BenchmarkError(
                f"BoringSSL compile command has invalid optimization flags "
                f"for {source}: {optimization_flags}"
            )
        if arguments.count("-DNDEBUG") != 1:
            raise BenchmarkError(
                f"BoringSSL compile command must define NDEBUG exactly once "
                f"for {source}"
            )
        if arguments.count("-c") != 1:
            raise BenchmarkError(
                f"BoringSSL compile command must contain exactly one -c "
                f"for {source}"
            )
        compile_index = arguments.index("-c")
        if compile_index + 1 >= len(arguments):
            raise BenchmarkError(
                f"BoringSSL compile command has no source after -c for {source}"
            )
        compiled_source = Path(arguments[compile_index + 1])
        if not compiled_source.is_absolute():
            compiled_source = boringssl_build_root / compiled_source
        if compiled_source.resolve() != resolved_source:
            raise BenchmarkError(
                f"BoringSSL compile command source does not match its "
                f"database entry for {source}: {compiled_source}"
            )
        output_indices = [
            index for index, argument in enumerate(arguments) if argument == "-o"
        ]
        output_values = [
            arguments[index + 1]
            for index in output_indices
            if index + 1 < len(arguments)
        ]
        if len(output_indices) != 1 or len(output_values) != 1:
            raise BenchmarkError(
                f"BoringSSL compile command must contain exactly one output "
                f"for {source}: {output_values}"
            )
        output_path = Path(output_values[0])
        if not output_path.is_absolute():
            output_path = boringssl_build_root / output_path
        resolved_output = output_path.resolve()
        try:
            resolved_output.relative_to(boringssl_build_root)
        except ValueError as error:
            raise BenchmarkError(
                f"BoringSSL compile output is outside the fresh build root "
                f"for {source}: {resolved_output}"
            ) from error
        if resolved_output.suffix != ".o":
            raise BenchmarkError(
                f"BoringSSL compile output is not an object for {source}: "
                f"{resolved_output}"
            )
        validated_object_outputs.append(str(resolved_output))
        validated_compile_outputs.append(
            {
                "source": source,
                "object": str(resolved_output),
            }
        )
        if arguments.count(expected_include_flag) != 1:
            raise BenchmarkError(
                f"BoringSSL compile command must use exactly one trusted "
                f"include root for {source}"
            )
        unexpected_include_flags = [
            argument
            for argument in arguments
            if argument.startswith("-I") and argument != expected_include_flag
        ]
        if unexpected_include_flags:
            raise BenchmarkError(
                f"BoringSSL compile command used unexpected include roots "
                f"for {source}: " + ", ".join(unexpected_include_flags)
            )
        present_escape_flags = [
            flag
            for flag in forbidden_escape_flags
            if any(
                argument == flag or argument.startswith(flag)
                for argument in arguments
            )
        ]
        if present_escape_flags:
            raise BenchmarkError(
                f"BoringSSL compile command used compiler escape flags for "
                f"{source}: " + ", ".join(present_escape_flags)
            )
        unexpected_assembler_flags = [
            argument
            for argument in arguments
            if argument.startswith("-Wa,")
            and argument != "-Wa,--noexecstack"
        ]
        if unexpected_assembler_flags:
            raise BenchmarkError(
                f"BoringSSL compile command used unexpected assembler flags "
                f"for {source}: " + ", ".join(unexpected_assembler_flags)
            )
        present_header_path_flags = [
            flag
            for flag in forbidden_header_path_flags
            if any(
                argument == flag
                or argument.startswith(f"{flag}=")
                or argument.startswith(flag)
                for argument in arguments
            )
        ]
        if present_header_path_flags:
            raise BenchmarkError(
                f"BoringSSL compile command used unexpected header inputs "
                f"for {source}: " + ", ".join(present_header_path_flags)
            )
        for option, expected in (
            ("-arch", EXPECTED_ARCHITECTURE),
            ("-isysroot", toolchain["macOSSDKPath"]),
        ):
            option_indices = [
                index
                for index, argument in enumerate(arguments)
                if argument == option
            ]
            values = [
                arguments[index + 1]
                for index in option_indices
                if index + 1 < len(arguments)
            ]
            if values != [expected]:
                raise BenchmarkError(
                    f"BoringSSL compile command has invalid {option} values "
                    f"for {source}: {values}"
                )
        deployment_flag = f"-mmacosx-version-min={DEPLOYMENT_TARGET}"
        if arguments.count(deployment_flag) != 1:
            raise BenchmarkError(
                f"BoringSSL compile command has invalid deployment target "
                f"for {source}"
            )
        present_forbidden = [
            flag
            for flag in forbidden_flags
            if any(
                argument == flag or argument.startswith(flag)
                for argument in arguments
            )
        ]
        if present_forbidden:
            raise BenchmarkError(
                f"BoringSSL compile command used forbidden flags for "
                f"{source}: " + ", ".join(present_forbidden)
            )
        present_assembly_disables = [
            definition
            for definition in forbidden_assembly_definitions
            if any(
                argument.startswith(definition)
                for argument in arguments
            )
        ]
        for index, argument in enumerate(arguments[:-1]):
            if argument != "-D":
                continue
            separated_definition = f"-D{arguments[index + 1]}"
            present_assembly_disables.extend(
                definition
                for definition in forbidden_assembly_definitions
                if separated_definition.startswith(definition)
            )
        if present_assembly_disables:
            raise BenchmarkError(
                "BoringSSL compile command disabled assembly for "
                f"{source}: " + ", ".join(present_assembly_disables)
            )
        source_suffix = resolved_source.suffix
        cxx_driver_mode_count = arguments.count("--driver-mode=g++")
        if source_suffix in (".cc", ".cpp") and cxx_driver_mode_count != 1:
            raise BenchmarkError(
                f"BoringSSL C++ compile command has invalid driver mode "
                f"for {source}: {cxx_driver_mode_count}"
            )
        if source_suffix not in (".cc", ".cpp") and cxx_driver_mode_count != 0:
            raise BenchmarkError(
                f"BoringSSL non-C++ compile command used C++ driver mode "
                f"for {source}"
            )
        consumed_indices = {
            0,
            compile_index,
            compile_index + 1,
            output_indices[0],
            output_indices[0] + 1,
            arguments.index(expected_include_flag),
        }
        for option in ("-arch", "-isysroot"):
            option_index = arguments.index(option)
            consumed_indices.add(option_index)
            consumed_indices.add(option_index + 1)
        consumed_indices.add(arguments.index(deployment_flag))
        unexpected_arguments = [
            argument
            for index, argument in enumerate(arguments)
            if index not in consumed_indices
            and argument not in allowed_fixed_arguments
        ]
        if unexpected_arguments:
            raise BenchmarkError(
                f"BoringSSL compile command differs from the exact argument "
                f"allowlist for {source}: "
                + ", ".join(unexpected_arguments)
            )
        common_target_arguments = [
            "-O3",
            "-DNDEBUG",
            "-arch",
            EXPECTED_ARCHITECTURE,
            "-isysroot",
            toolchain["macOSSDKPath"],
            f"-mmacosx-version-min={DEPLOYMENT_TARGET}",
        ]
        output_and_source_arguments = [
            "-o",
            output_values[0],
            "-c",
            arguments[compile_index + 1],
        ]
        if resolved_source == expected_driver_source:
            expected_argument_variants = [
                [
                    arguments[0],
                    "--driver-mode=g++",
                    expected_include_flag,
                    *common_target_arguments,
                    *output_and_source_arguments,
                ]
            ]
        elif source_suffix == ".S":
            expected_argument_variants = [
                [
                    arguments[0],
                    "-DBORINGSSL_IMPLEMENTATION",
                    expected_include_flag,
                    "-Wa,--noexecstack",
                    *common_target_arguments,
                    *output_and_source_arguments,
                ]
            ]
        else:
            # CMake emits -std before target flags for this pinned BoringSSL.
            cxx_policy_arguments = [
                "-fno-strict-aliasing",
                "-ggdb",
                "-fno-common",
                "-fvisibility=hidden",
                "-O3",
                "-DNDEBUG",
                "-std=gnu++17",
                "-arch",
                EXPECTED_ARCHITECTURE,
                "-isysroot",
                toolchain["macOSSDKPath"],
                f"-mmacosx-version-min={DEPLOYMENT_TARGET}",
                "-Werror",
                "-Wformat=2",
                "-Wmissing-field-initializers",
                "-Wshadow",
                "-Wsign-compare",
                "-Wtype-limits",
                "-Wvla",
                "-Wwrite-strings",
                "-Wimplicit-fallthrough",
                "-Wall",
                "-Wnewline-eof",
                "-Wextra-semi",
                "-fcolor-diagnostics",
                "-Wheader-hygiene",
                "-Wmissing-prototypes",
                "-Wstring-concatenation",
                "-Wframe-larger-than=25344",
                "-Wctad-maybe-unsupported",
            ]
            cxx_prefix = [
                arguments[0],
                "--driver-mode=g++",
            ]
            expected_argument_variants = [
                [
                    *cxx_prefix,
                    expected_include_flag,
                    *cxx_policy_arguments,
                    *output_and_source_arguments,
                ],
                *[
                    [
                        *cxx_prefix,
                        "-DBORINGSSL_IMPLEMENTATION",
                        expected_include_flag,
                        *cxx_policy_arguments,
                        *tail_arguments,
                        *output_and_source_arguments,
                    ]
                    for tail_arguments in (
                        (),
                        ("-fno-aligned-new",),
                        ("-fno-exceptions", "-fno-rtti"),
                    )
                ],
            ]
        if arguments not in expected_argument_variants:
            raise BenchmarkError(
                f"BoringSSL compile command does not match a pinned command "
                f"shape for {source}"
            )
    if len(validated_object_outputs) != len(set(validated_object_outputs)):
        raise BenchmarkError("BoringSSL compile outputs are not unique")
    object_by_source = {
        item["source"]: item["object"]
        for item in validated_compile_outputs
    }
    required_object_outputs = {
        relative_source: object_by_source[str(expected_source)]
        for relative_source, expected_source in required_sources.items()
    }
    driver_command = " ".join(driver_entries[0][1])
    return {
        "configuration": "Release",
        "architecture": EXPECTED_ARCHITECTURE,
        "deploymentTarget": DEPLOYMENT_TARGET,
        "sdkPath": toolchain["macOSSDKPath"],
        "driverCompileCommand": driver_command,
        "validatedCompileCommandCount": len(compile_arguments),
        "validatedRequiredSources": validated_source_entries,
        "trustedSwiftSourceRoot": str(swift_source_root),
        "trustedBoringSSLSourceRoot": str(boringssl_source_root),
        "freshBoringSSLBuildRoot": str(boringssl_build_root),
        "trustedIncludeRoot": str(boringssl_source_root / "include"),
        "validatedObjectOutputs": validated_object_outputs,
        "validatedCompileOutputs": validated_compile_outputs,
        "validatedRequiredObjectOutputs": required_object_outputs,
        "allCompileCommandsUseO3": True,
        "responseFilesAbsent": True,
        "assemblyEnabled": True,
        "forbiddenAssemblyDefinitionsAbsent": list(
            forbidden_assembly_definitions
        ),
        "forbiddenFlagsAbsent": list(forbidden_flags),
    }


def require_boringssl_link_contract(
    *,
    completed: subprocess.CompletedProcess[str],
    build_directory: Path,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    verbose_log = completed.stdout + "\n" + completed.stderr
    compiler_path = str(Path(toolchain["clangxxCompiler"]).resolve())
    link_lines = [
        line
        for line in verbose_log.splitlines()
        if compiler_path in line
        and re.search(
            r"(?:^|\s)-o\s+boringssl-sha256-benchmark(?:\s|$)",
            line,
        )
        is not None
        and " -c " not in line
    ]
    if len(link_lines) != 1:
        raise BenchmarkError(
            "BoringSSL build log must contain exactly one final worker link "
            f"command; found {len(link_lines)}"
        )
    command_text = link_lines[0][link_lines[0].index(compiler_path) :]
    if " && " in command_text:
        command_text = command_text.split(" && ", 1)[0]
    try:
        arguments = shlex.split(command_text)
    except ValueError as error:
        raise BenchmarkError(
            "could not parse the BoringSSL worker link command"
        ) from error
    if not arguments or str(Path(arguments[0]).resolve()) != compiler_path:
        raise BenchmarkError(
            "BoringSSL worker link command used an unexpected compiler"
        )
    response_files = [
        argument for argument in arguments if argument.startswith("@")
    ]
    if response_files:
        raise BenchmarkError(
            "BoringSSL worker link command used forbidden response files: "
            + ", ".join(response_files)
        )
    optimization_flags = [
        argument
        for argument in arguments
        if argument == "-O"
        or re.fullmatch(r"-O(?:[0-9]+|s|z|g|fast)", argument) is not None
    ]
    if optimization_flags != ["-O3"]:
        raise BenchmarkError(
            "BoringSSL worker link command has invalid optimization flags: "
            f"{optimization_flags}"
        )
    if arguments.count("--driver-mode=g++") != 1:
        raise BenchmarkError(
            "BoringSSL worker link command has invalid C++ driver mode"
        )
    if arguments.count("-DNDEBUG") != 1:
        raise BenchmarkError(
            "BoringSSL worker link command must define NDEBUG exactly once"
        )
    for option, expected in (
        ("-arch", EXPECTED_ARCHITECTURE),
        ("-isysroot", toolchain["macOSSDKPath"]),
    ):
        option_indices = [
            index
            for index, argument in enumerate(arguments)
            if argument == option
        ]
        values = [
            arguments[index + 1]
            for index in option_indices
            if index + 1 < len(arguments)
        ]
        if values != [expected]:
            raise BenchmarkError(
                f"BoringSSL worker link command has invalid {option}: {values}"
            )
    deployment_flag = f"-mmacosx-version-min={DEPLOYMENT_TARGET}"
    if arguments.count(deployment_flag) != 1:
        raise BenchmarkError(
            "BoringSSL worker link command has an invalid deployment target"
        )
    forbidden_flags = (
        "--config",
        "--coverage",
        "-fcoverage",
        "-fprofile",
        "-fsanitize",
        "-ftest-coverage",
    )
    present_forbidden = [
        flag
        for flag in forbidden_flags
        if any(argument.startswith(flag) for argument in arguments)
    ]
    if present_forbidden:
        raise BenchmarkError(
            "BoringSSL worker link command used forbidden flags: "
            + ", ".join(present_forbidden)
        )

    def resolved_option_path(value: str) -> Path:
        path = Path(value)
        return (
            path.resolve()
            if path.is_absolute()
            else (build_directory / path).resolve()
        )

    output_indices = [
        index for index, argument in enumerate(arguments) if argument == "-o"
    ]
    output_values = [
        arguments[index + 1]
        for index in output_indices
        if index + 1 < len(arguments)
    ]
    expected_output = (build_directory / "boringssl-sha256-benchmark").resolve()
    if len(output_values) != 1 or resolved_option_path(
        output_values[0]
    ) != expected_output:
        raise BenchmarkError(
            "BoringSSL worker link command has an unexpected output: "
            f"{output_values}"
        )
    object_inputs = [
        resolved_option_path(argument)
        for argument in arguments
        if argument.endswith(".o")
    ]
    archive_inputs = [
        resolved_option_path(argument)
        for argument in arguments
        if argument.endswith(".a")
    ]
    expected_driver_object = (
        build_directory
        / "CMakeFiles/boringssl-sha256-benchmark.dir/SHA256Benchmark.cpp.o"
    ).resolve()
    expected_crypto_archive = (
        build_directory / "boringssl/libcrypto.a"
    ).resolve()
    if object_inputs != [expected_driver_object]:
        raise BenchmarkError(
            "BoringSSL worker link command has unexpected object inputs: "
            + ", ".join(str(path) for path in object_inputs)
        )
    if archive_inputs != [expected_crypto_archive]:
        raise BenchmarkError(
            "BoringSSL worker link command has unexpected archive inputs: "
            + ", ".join(str(path) for path in archive_inputs)
        )
    for label, path in (
        ("driverObject", expected_driver_object),
        ("cryptoArchive", expected_crypto_archive),
    ):
        if not path.is_file():
            raise BenchmarkError(
                f"BoringSSL worker link input does not exist: {path}"
            )
    expected_arguments = [
        compiler_path,
        "--driver-mode=g++",
        "-O3",
        "-DNDEBUG",
        "-arch",
        EXPECTED_ARCHITECTURE,
        "-isysroot",
        toolchain["macOSSDKPath"],
        f"-mmacosx-version-min={DEPLOYMENT_TARGET}",
        "-Wl,-search_paths_first",
        "-Wl,-headerpad_max_install_names",
        (
            "CMakeFiles/boringssl-sha256-benchmark.dir/"
            "SHA256Benchmark.cpp.o"
        ),
        "-o",
        "boringssl-sha256-benchmark",
        "boringssl/libcrypto.a",
    ]
    if arguments != expected_arguments:
        raise BenchmarkError(
            "BoringSSL worker link command differs from the exact allowlist: "
            + json.dumps(
                {
                    "expected": expected_arguments,
                    "actual": arguments,
                },
                sort_keys=True,
            )
        )
    return {
        "command": arguments,
        "rawLogLine": link_lines[0],
        "output": str(expected_output),
        "inputs": {
            "driverObject": {
                "path": str(expected_driver_object),
                "sha256": file_sha256(expected_driver_object),
            },
            "cryptoArchive": {
                "path": str(expected_crypto_archive),
                "sha256": file_sha256(expected_crypto_archive),
            },
        },
        "responseFilesAbsent": True,
        "passed": True,
    }


def require_boringssl_dependency_contract(
    *,
    completed: subprocess.CompletedProcess[str],
    build_directory: Path,
    compile_outputs: Sequence[dict[str, str]],
    required_object_outputs: dict[str, str],
    boringssl_source: Path,
    driver_source: Path,
    sdk_root: Path,
    clang_resource_directory: Path,
) -> dict[str, Any]:
    if completed.stderr:
        raise BenchmarkError(
            "Ninja dependency inspection emitted unexpected stderr"
        )
    build_root = build_directory.resolve()
    records: dict[Path, list[Path]] = {}
    declared_counts: dict[Path, int] = {}
    current_object: Path | None = None
    header_pattern = re.compile(
        r"^(.+): #deps ([0-9]+), deps mtime .+ \((VALID|STALE)\)$"
    )
    for line in completed.stdout.splitlines():
        if not line:
            current_object = None
            continue
        if line.startswith("    "):
            if current_object is None:
                raise BenchmarkError(
                    "Ninja dependency output contains an orphan dependency"
                )
            dependency_text = line.strip()
            dependency_path = Path(dependency_text)
            if not dependency_path.is_absolute():
                dependency_path = build_root / dependency_path
            records[current_object].append(dependency_path.resolve())
            continue
        match = header_pattern.fullmatch(line)
        if match is None:
            raise BenchmarkError(
                f"malformed Ninja dependency record: {line}"
            )
        object_path = Path(match.group(1))
        if not object_path.is_absolute():
            object_path = build_root / object_path
        resolved_object = object_path.resolve()
        try:
            resolved_object.relative_to(build_root)
        except ValueError as error:
            raise BenchmarkError(
                "Ninja dependency record is outside the fresh build root: "
                f"{resolved_object}"
            ) from error
        if resolved_object in records:
            raise BenchmarkError(
                f"Ninja dependency output repeats an object: {resolved_object}"
            )
        if match.group(3) != "VALID":
            raise BenchmarkError(
                f"Ninja dependency record is stale: {resolved_object}"
            )
        current_object = resolved_object
        records[current_object] = []
        declared_counts[current_object] = int(match.group(2), 10)

    if not records:
        raise BenchmarkError("Ninja dependency inspection produced no records")
    for object_path, dependencies in records.items():
        if declared_counts[object_path] != len(dependencies):
            raise BenchmarkError(
                f"Ninja dependency count mismatch for {object_path}: "
                f"declared {declared_counts[object_path]}, found "
                f"{len(dependencies)}"
            )

    compile_output_paths = {
        Path(item["object"]).resolve()
        for item in compile_outputs
    }
    source_by_object = {
        Path(item["object"]).resolve(): Path(item["source"]).resolve()
        for item in compile_outputs
    }
    if len(source_by_object) != len(compile_outputs):
        raise BenchmarkError(
            "BoringSSL compile output mapping contains duplicate objects"
        )
    built_compile_outputs = {
        path for path in compile_output_paths if path.is_file()
    }
    if set(records) != built_compile_outputs:
        missing_records = sorted(
            str(path) for path in built_compile_outputs.difference(records)
        )
        unexpected_records = sorted(
            str(path) for path in set(records).difference(built_compile_outputs)
        )
        raise BenchmarkError(
            "Ninja dependency object set does not match the built compile "
            "outputs: "
            + json.dumps(
                {
                    "missing": missing_records,
                    "unexpected": unexpected_records,
                },
                sort_keys=True,
            )
        )
    for object_path, dependencies in records.items():
        expected_source = source_by_object[object_path]
        if expected_source not in dependencies:
            raise BenchmarkError(
                f"Ninja dependency record does not include the exact compile "
                f"source for {object_path}: {expected_source}"
            )

    allowed_roots = {
        "boringSSLSource": boringssl_source.resolve(),
        "benchmarkDriver": driver_source.resolve().parent,
        "macOSSDK": sdk_root.resolve(),
        "clangResourceDirectory": clang_resource_directory.resolve(),
    }
    for label, root in allowed_roots.items():
        if not root.is_dir():
            raise BenchmarkError(
                f"trusted dependency root does not exist for {label}: {root}"
            )
    root_counts = {label: 0 for label in allowed_roots}
    dependency_count = 0
    unique_dependencies: set[Path] = set()
    for object_path, dependencies in records.items():
        for dependency in dependencies:
            if not dependency.is_file():
                raise BenchmarkError(
                    f"Ninja dependency does not exist: {dependency}"
                )
            matched_label = None
            for label, root in allowed_roots.items():
                try:
                    dependency.relative_to(root)
                except ValueError:
                    continue
                matched_label = label
                break
            if matched_label is None:
                raise BenchmarkError(
                    "BoringSSL build consumed a dependency outside the "
                    f"trusted roots for {object_path}: {dependency}"
                )
            root_counts[matched_label] += 1
            dependency_count += 1
            unique_dependencies.add(dependency)

    dependency_content_hashes = {
        dependency: file_sha256(dependency)
        for dependency in sorted(unique_dependencies)
    }
    dependency_content_manifest = "\n".join(
        f"{dependency}\0{dependency_content_hashes[dependency]}"
        for dependency in sorted(dependency_content_hashes)
    )
    required_evidence: dict[str, Any] = {}
    for label, object_text in required_object_outputs.items():
        object_path = Path(object_text).resolve()
        dependencies = records.get(object_path)
        if dependencies is None:
            raise BenchmarkError(
                f"required BoringSSL object has no dependency record: "
                f"{object_path}"
            )
        manifest = "\n".join(
            f"{dependency}\0{dependency_content_hashes[dependency]}"
            for dependency in sorted(set(dependencies))
        )
        required_evidence[label] = {
            "object": str(object_path),
            "dependencyCount": len(dependencies),
            "dependencyManifestSHA256": hashlib.sha256(
                manifest.encode("utf-8")
            ).hexdigest(),
        }

    return {
        "ninjaOutputSHA256": hashlib.sha256(
            completed.stdout.encode("utf-8")
        ).hexdigest(),
        "ninjaOutputByteCount": len(completed.stdout.encode("utf-8")),
        "recordCount": len(records),
        "builtCompileOutputCount": len(built_compile_outputs),
        "validatedDependencyCount": dependency_count,
        "uniqueDependencyCount": len(unique_dependencies),
        "dependencyFiles": [
            str(dependency) for dependency in sorted(unique_dependencies)
        ],
        "dependencyContentManifestSHA256": hashlib.sha256(
            dependency_content_manifest.encode("utf-8")
        ).hexdigest(),
        "allowedRoots": {
            label: str(root) for label, root in allowed_roots.items()
        },
        "dependencyCountsByRoot": root_counts,
        "requiredObjects": required_evidence,
        "disallowedDependencyCount": 0,
        "allRecordsValid": True,
        "passed": True,
    }


def load_macho_text_function(
    path: Path,
    *,
    toolchain: dict[str, Any],
    required_symbol_fragments: Sequence[str] = (),
    exact_symbol: str | None = None,
    label: str,
) -> dict[str, Any]:
    if exact_symbol is None and not required_symbol_fragments:
        raise BenchmarkError(f"{label} has no symbol selection contract")
    if exact_symbol is not None and required_symbol_fragments:
        raise BenchmarkError(
            f"{label} cannot combine exact and fragment symbol selection"
        )
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": toolchain["developerDirectory"],
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    symbols_output = run_command(
        [toolchain["nm"]["invocationPath"], "-nm", str(path)],
        environment=environment,
        executable_path=toolchain["nm"]["path"],
    ).stdout
    text_symbols: list[tuple[int, str]] = []
    symbol_pattern = re.compile(
        r"^([0-9a-fA-F]{16}) \(__TEXT,__text\).* (.+)$"
    )
    for line in symbols_output.splitlines():
        match = symbol_pattern.fullmatch(line)
        if match is not None:
            text_symbols.append((int(match.group(1), 16), match.group(2)))
    if exact_symbol is not None:
        candidates = [
            (address, symbol)
            for address, symbol in text_symbols
            if symbol == exact_symbol
        ]
    else:
        candidates = [
            (address, symbol)
            for address, symbol in text_symbols
            if all(fragment in symbol for fragment in required_symbol_fragments)
        ]
    if len(candidates) != 1:
        raise BenchmarkError(
            f"could not identify exactly one {label} symbol; "
            f"found {len(candidates)}"
        )
    function_start, function_symbol = candidates[0]
    following_addresses = [
        address for address, _ in text_symbols if address > function_start
    ]
    if not following_addresses:
        raise BenchmarkError(f"could not determine the {label} symbol boundary")
    function_end = min(following_addresses)

    disassembly_output = run_command(
        [toolchain["otool"]["invocationPath"], "-tvV", str(path)],
        environment=environment,
        executable_path=toolchain["otool"]["path"],
    ).stdout
    instruction_pattern = re.compile(r"^([0-9a-fA-F]{16})\s+(.+)$")
    instructions: list[tuple[int, str, str]] = []
    for line in disassembly_output.splitlines():
        match = instruction_pattern.fullmatch(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if function_start <= address < function_end:
            instructions.append((address, match.group(2), line))
    if not instructions:
        raise BenchmarkError(f"{label} disassembly is empty")
    return {
        "symbol": function_symbol,
        "functionStart": function_start,
        "functionEnd": function_end,
        "instructions": instructions,
    }


def find_backedges(
    instructions: Sequence[tuple[int, str, str]],
    *,
    function_start: int,
) -> list[tuple[int, int]]:
    branch_pattern = re.compile(
        r"^(?:b|b\.[a-z0-9]+|bc\.[a-z0-9]+|cbnz|cbz|tbnz|tbz)\s+"
    )
    target_pattern = re.compile(r"0x([0-9a-fA-F]+)(?:\s|$)")
    backedges: list[tuple[int, int]] = []
    for address, instruction, _ in instructions:
        if branch_pattern.match(instruction) is None:
            continue
        target_match = target_pattern.search(instruction)
        if target_match is None:
            continue
        target = int(target_match.group(1), 16)
        if function_start <= target < address:
            backedges.append((target, address))
    return backedges


def is_call_instruction(instruction: str) -> bool:
    return (
        re.match(
            r"^(?:bl|blr|blraa|blraaz|blrab|blrabz)\s+",
            instruction,
        )
        is not None
    )


def is_return_instruction(instruction: str) -> bool:
    return (
        re.match(
            r"^(?:ret|retaa|retab|eret|eretaa|eretab|drps)(?:\s|$)",
            instruction,
        )
        is not None
    )


def is_external_branch_transfer(
    *,
    instruction: str,
    function_start: int,
    function_end: int,
) -> bool:
    if (
        re.match(
            r"^(?:br|braa|braaz|brab|brabz)\s+",
            instruction,
        )
        is not None
    ):
        return True
    branch_match = re.match(
        r"^(?:b|b\.[a-z0-9]+|bc\.[a-z0-9]+|cbnz|cbz|tbnz|tbz)"
        r"\s+(.+)$",
        instruction,
    )
    if branch_match is None:
        return False
    operands = branch_match.group(1).split(";", 1)[0].strip()
    target_text = operands.rsplit(",", 1)[-1].strip()
    numeric_match = re.fullmatch(r"0x([0-9a-fA-F]+)", target_text)
    if numeric_match is None:
        return True
    target = int(numeric_match.group(1), 16)
    return not function_start <= target < function_end


def validate_direct_call_contract(
    instructions: Sequence[tuple[int, str, str]],
    *,
    label: str,
    required_calls: Sequence[tuple[str, str, int]],
) -> list[dict[str, Any]]:
    if not instructions:
        raise BenchmarkError(f"{label} has no instructions")
    function_start = min(address for address, _, _ in instructions)
    function_end = max(address for address, _, _ in instructions) + 4
    calls = [
        (address, instruction)
        for address, instruction, _ in instructions
        if is_call_instruction(instruction)
    ]
    tail_transfers = [
        instruction
        for _, instruction, _ in instructions
        if is_external_branch_transfer(
            instruction=instruction,
            function_start=function_start,
            function_end=function_end,
        )
    ]
    if tail_transfers:
        raise BenchmarkError(
            f"{label} contains unvalidated external branch transfers: "
            + ", ".join(tail_transfers)
        )
    matched_indices: set[int] = set()
    evidence: list[dict[str, Any]] = []
    for call_label, fragment, expected_count in required_calls:
        indices = [
            index
            for index, (_, instruction) in enumerate(calls)
            if fragment in instruction
        ]
        if len(indices) != expected_count:
            raise BenchmarkError(
                f"{label} must contain exactly {expected_count} "
                f"{call_label} call(s); found {len(indices)}"
            )
        matched_indices.update(indices)
        evidence.append(
            {
                "label": call_label,
                "symbolFragment": fragment,
                "expectedCount": expected_count,
                "addresses": [
                    f"0x{calls[index][0]:x}" for index in indices
                ],
            }
        )
    unmatched = [
        instruction
        for index, (_, instruction) in enumerate(calls)
        if index not in matched_indices
    ]
    if unmatched:
        raise BenchmarkError(
            f"{label} contains unvalidated direct calls: "
            + ", ".join(unmatched)
        )
    return evidence


def analyze_swift_worker_codegen(
    path: Path,
    *,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    function = load_macho_text_function(
        path,
        toolchain=toolchain,
        required_symbol_fragments=(
            "SSLSHA256Benchmark",
            "SHA256C7CommandO3run",
        ),
        label="Swift benchmark run",
    )
    function_start = function["functionStart"]
    function_end = function["functionEnd"]
    instructions = function["instructions"]

    backedges = find_backedges(
        instructions,
        function_start=function_start,
    )
    if len(backedges) != 1:
        raise BenchmarkError(
            "Swift benchmark run must contain exactly one timed-loop backedge; "
            f"found {len(backedges)}"
        )
    loop_start, loop_end = backedges[0]
    loop_lines = [
        line
        for address, _, line in instructions
        if loop_start <= address <= loop_end
    ]
    loop_disassembly = "\n".join(loop_lines)
    forbidden_in_loop = [
        symbol for symbol in LOOP_FORBIDDEN_SYMBOLS if symbol in loop_disassembly
    ]
    if forbidden_in_loop:
        raise BenchmarkError(
            "Swift timed loop contains forbidden ownership/copy operations: "
            + ", ".join(forbidden_in_loop)
        )
    loop_calls = [
        (address, instruction)
        for address, instruction, _ in instructions
        if loop_start <= address <= loop_end
        and is_call_instruction(instruction)
    ]
    loop_branch_transfers = [
        (address, instruction)
        for address, instruction, _ in instructions
        if loop_start <= address <= loop_end
        and (
            is_external_branch_transfer(
                instruction=instruction,
                function_start=function_start,
                function_end=function_end,
            )
            or is_return_instruction(instruction)
        )
    ]
    required_loop_calls = {
        "SHA256Context.update": "SHA256ContextV6update",
        "SHA256Context.finalizeInPlace": "SHA256ContextV15finalizeInPlace",
    }
    validated_loop_calls: list[dict[str, str]] = []
    unmatched_loop_calls = list(loop_calls)
    for label, fragment in required_loop_calls.items():
        matching = [
            (address, instruction)
            for address, instruction in loop_calls
            if fragment in instruction
        ]
        if len(matching) != 1:
            raise BenchmarkError(
                f"Swift timed loop must call {label} exactly once; "
                f"found {len(matching)} call sites"
            )
        address, instruction = matching[0]
        validated_loop_calls.append(
            {
                "label": label,
                "address": f"0x{address:x}",
                "instruction": instruction,
            }
        )
        unmatched_loop_calls.remove((address, instruction))
    if unmatched_loop_calls:
        raise BenchmarkError(
            "Swift timed loop contains unvalidated helper calls: "
            + ", ".join(instruction for _, instruction in unmatched_loop_calls)
        )
    if loop_branch_transfers:
        raise BenchmarkError(
            "Swift timed loop contains external branch transfers: "
            + ", ".join(
                instruction for _, instruction in loop_branch_transfers
            )
        )
    prefix_disassembly = "\n".join(
        line for address, _, line in instructions if address < loop_start
    )
    uniqueness_checks_before_loop = prefix_disassembly.count(
        "swift_isUniquelyReferenced"
    )
    if uniqueness_checks_before_loop > 2:
        raise BenchmarkError(
            "Swift worker performs more than two uniqueness checks before "
            "the timed loop"
        )
    return {
        "symbol": function["symbol"],
        "functionStartAddress": f"0x{function_start:x}",
        "functionEndAddress": f"0x{function_end:x}",
        "loopStartAddress": f"0x{loop_start:x}",
        "loopBackedgeAddress": f"0x{loop_end:x}",
        "uniquenessChecksBeforeLoop": uniqueness_checks_before_loop,
        "forbiddenSymbolsInLoop": forbidden_in_loop,
        "forbiddenSymbolPolicy": list(LOOP_FORBIDDEN_SYMBOLS),
        "validatedDirectCallsInLoop": validated_loop_calls,
        "unvalidatedDirectCallCount": len(unmatched_loop_calls),
        "externalBranchTransferCount": len(loop_branch_transfers),
        "loopDisassembly": loop_disassembly,
        "passed": True,
    }


def analyze_sha256_multiblock_codegen(
    path: Path,
    *,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    kernel = load_macho_text_function(
        path,
        toolchain=toolchain,
        required_symbol_fragments=(
            "SSLCrypto17SHA256ARM64Kernel",
            "compressMultipleBlocks",
        ),
        label="SHA-256 ARM64 multi-block kernel",
    )
    kernel_start = kernel["functionStart"]
    kernel_end = kernel["functionEnd"]
    kernel_instructions = kernel["instructions"]
    backedges = find_backedges(
        kernel_instructions,
        function_start=kernel_start,
    )
    if len(backedges) != 1:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block kernel must contain exactly one "
            f"block-loop backedge; found {len(backedges)}"
        )
    loop_start, loop_end = backedges[0]
    prefix_instructions = [
        instruction
        for address, instruction, _ in kernel_instructions
        if address < loop_start
    ]
    loop_instructions = [
        (address, instruction, line)
        for address, instruction, line in kernel_instructions
        if loop_start <= address <= loop_end
    ]
    loop_disassembly = "\n".join(line for _, _, line in loop_instructions)
    prefix_constant_loads = [
        instruction
        for instruction in prefix_instructions
        if re.match(r"^ldr\s+q[0-9]+,", instruction) is not None
    ]
    if len(prefix_constant_loads) != 16:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block kernel must hoist exactly 16 vector "
            f"constant loads before the block loop; found "
            f"{len(prefix_constant_loads)}"
        )

    loop_call_count = sum(
        1
        for _, instruction, _ in loop_instructions
        if is_call_instruction(instruction)
        or is_external_branch_transfer(
            instruction=instruction,
            function_start=kernel_start,
            function_end=kernel_end,
        )
        or is_return_instruction(instruction)
    )
    loop_page_address_count = sum(
        1
        for _, instruction, _ in loop_instructions
        if re.match(r"^adrp\s+", instruction) is not None
    )
    loop_memory_instructions = [
        instruction
        for _, instruction, _ in loop_instructions
        if "[" in instruction
    ]
    input_vector_load_offsets: list[int] = []
    unexpected_memory_operations: list[str] = []
    input_vector_load_pattern = re.compile(
        r"^ldp\s+q[0-9]+,\s*q[0-9]+,\s*"
        r"\[x0(?:,\s*#(0x[0-9a-fA-F]+))?\]$"
    )
    for instruction in loop_memory_instructions:
        match = input_vector_load_pattern.fullmatch(instruction)
        if match is None:
            unexpected_memory_operations.append(instruction)
            continue
        offset_text = match.group(1)
        input_vector_load_offsets.append(
            int(offset_text, 16) if offset_text is not None else 0
        )
    forbidden_in_loop = [
        symbol
        for symbol in (*LOOP_FORBIDDEN_SYMBOLS, "swift_once")
        if symbol in loop_disassembly
    ]
    sha256h_count = sum(
        1
        for _, instruction, _ in loop_instructions
        if instruction.startswith("sha256h.4s")
    )
    sha256h2_count = sum(
        1
        for _, instruction, _ in loop_instructions
        if instruction.startswith("sha256h2.4s")
    )
    if loop_call_count != 0:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop contains a function call"
        )
    if loop_page_address_count != 0:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop reloads a page-relative address"
        )
    if sorted(input_vector_load_offsets) != [0, 32]:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop must perform exactly two "
            "64-byte input vector-pair loads at offsets 0 and 32; found "
            f"{input_vector_load_offsets}"
        )
    if unexpected_memory_operations:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop contains unexpected memory "
            "operations: " + ", ".join(unexpected_memory_operations)
        )
    if forbidden_in_loop:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop contains forbidden "
            "initialization/ownership/copy operations: "
            + ", ".join(forbidden_in_loop)
        )
    if sha256h_count != 16 or sha256h2_count != 16:
        raise BenchmarkError(
            "SHA-256 ARM64 multi-block loop must contain exactly 16 "
            f"sha256h and 16 sha256h2 instructions; found "
            f"{sha256h_count} and {sha256h2_count}"
        )

    context_update = load_macho_text_function(
        path,
        toolchain=toolchain,
        required_symbol_fragments=(
            "SSLCrypto13SHA256ContextV6update",
            "CryptoInputError",
        ),
        label="SHA-256 context update",
    )
    context_instructions = context_update["instructions"]
    context_call_contract = validate_direct_call_contract(
        context_instructions,
        label="SHA-256 context update",
        required_calls=(
            ("typed-error witness", "CryptoInputErrorOACs0E0AAWl", 1),
            ("typed-error throw", "swift_willThrowTypedImpl", 1),
            ("bounded pending-byte copy", "_memmove", 2),
            ("multi-block kernel", "compressMultipleBlocks", 1),
            ("stack-check failure", "stack_chk_fail", 1),
        ),
    )
    helper_call_indices = [
        index
        for index, (_, instruction, _) in enumerate(context_instructions)
        if instruction.startswith("bl")
        and "compressMultipleBlocks" in instruction
    ]
    if len(helper_call_indices) != 1:
        raise BenchmarkError(
            "SHA-256 context update must call the multi-block kernel exactly "
            f"once; found {len(helper_call_indices)} call sites"
        )
    helper_call_index = helper_call_indices[0]
    helper_call_address = context_instructions[helper_call_index][0]
    context_backedges = find_backedges(
        context_instructions,
        function_start=context_update["functionStart"],
    )
    containing_backedges = [
        (loop_target, branch_address)
        for loop_target, branch_address in context_backedges
        if loop_target <= helper_call_address <= branch_address
    ]
    if containing_backedges:
        raise BenchmarkError(
            "SHA-256 context invokes the multi-block helper from inside a loop"
        )
    post_helper_vector_memory = [
        (index, address, instruction, line)
        for index, (address, instruction, line) in enumerate(
            context_instructions[helper_call_index + 1 :],
            start=helper_call_index + 1,
        )
        if "[" in instruction
        and re.search(r"\b[bhdqsv][0-9]+\b", instruction) is not None
    ]
    if len(post_helper_vector_memory) != 1:
        raise BenchmarkError(
            "SHA-256 context update must perform exactly one vector-memory "
            "operation after the multi-block kernel call; found "
            f"{len(post_helper_vector_memory)} operations"
        )
    state_store_index, state_store_address, state_store_instruction, _ = (
        post_helper_vector_memory[0]
    )
    if (
        re.match(
            r"^stp\s+q0,\s*q1,\s*\[",
            state_store_instruction,
        )
        is None
    ):
        raise BenchmarkError(
            "SHA-256 context update uses an unexpected vector-memory "
            f"operation after the multi-block kernel call: "
            f"{state_store_instruction}"
        )
    if state_store_index > helper_call_index + 4:
        raise BenchmarkError(
            "SHA-256 context update does not store both returned state "
            "vectors immediately after the multi-block kernel call"
        )
    finalize = load_macho_text_function(
        path,
        toolchain=toolchain,
        required_symbol_fragments=(
            "SSLCrypto13SHA256ContextV15finalizeInPlace",
            "CryptoInputError",
        ),
        label="SHA-256 context finalize",
    )
    finalize_call_contract = validate_direct_call_contract(
        finalize["instructions"],
        label="SHA-256 context finalize",
        required_calls=(
            ("padding zero fill", "_bzero", 2),
            ("typed-error witness", "CryptoInputErrorOACs0E0AAWl", 1),
            ("typed-error throw", "swift_willThrowTypedImpl", 1),
            ("stack-check failure", "stack_chk_fail", 1),
        ),
    )
    return {
        "kernelSymbol": kernel["symbol"],
        "kernelFunctionStartAddress": f"0x{kernel_start:x}",
        "kernelFunctionEndAddress": f"0x{kernel_end:x}",
        "blockLoopStartAddress": f"0x{loop_start:x}",
        "blockLoopBackedgeAddress": f"0x{loop_end:x}",
        "constantVectorLoadsBeforeLoop": len(prefix_constant_loads),
        "functionCallsInLoop": loop_call_count,
        "pageAddressLoadsInLoop": loop_page_address_count,
        "inputVectorPairLoadOffsets": sorted(input_vector_load_offsets),
        "unexpectedMemoryOperations": unexpected_memory_operations,
        "sha256hInstructionsPerBlock": sha256h_count,
        "sha256h2InstructionsPerBlock": sha256h2_count,
        "forbiddenSymbolsInLoop": forbidden_in_loop,
        "forbiddenSymbolPolicy": [
            *LOOP_FORBIDDEN_SYMBOLS,
            "swift_once",
        ],
        "contextUpdateSymbol": context_update["symbol"],
        "contextUpdateFunctionStartAddress": (
            f"0x{context_update['functionStart']:x}"
        ),
        "contextUpdateFunctionEndAddress": (
            f"0x{context_update['functionEnd']:x}"
        ),
        "contextUpdateDirectCallContract": context_call_contract,
        "multiBlockKernelCallSites": len(helper_call_indices),
        "multiBlockKernelCallAddress": f"0x{helper_call_address:x}",
        "contextBackedgesContainingKernelCall": len(containing_backedges),
        "stateVectorStoreAddress": f"0x{state_store_address:x}",
        "stateVectorStoreCount": len(post_helper_vector_memory),
        "contextFinalizeSymbol": finalize["symbol"],
        "contextFinalizeFunctionStartAddress": (
            f"0x{finalize['functionStart']:x}"
        ),
        "contextFinalizeFunctionEndAddress": (
            f"0x{finalize['functionEnd']:x}"
        ),
        "contextFinalizeDirectCallContract": finalize_call_contract,
        "blockLoopDisassembly": loop_disassembly,
        "passed": True,
    }


def analyze_boringssl_sha256_backend_codegen(
    path: Path,
    *,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    function = load_macho_text_function(
        path,
        toolchain=toolchain,
        exact_symbol="_sha256_block_data_order_hw",
        label="BoringSSL ARM64 SHA-256 hardware kernel",
    )
    instructions = function["instructions"]
    instruction_counts = {
        "sha256h": sum(
            1
            for _, instruction, _ in instructions
            if instruction.startswith("sha256h.")
        ),
        "sha256h2": sum(
            1
            for _, instruction, _ in instructions
            if instruction.startswith("sha256h2.")
        ),
        "sha256su0": sum(
            1
            for _, instruction, _ in instructions
            if instruction.startswith("sha256su0.")
        ),
        "sha256su1": sum(
            1
            for _, instruction, _ in instructions
            if instruction.startswith("sha256su1.")
        ),
    }
    expected_counts = {
        "sha256h": 16,
        "sha256h2": 16,
        "sha256su0": 12,
        "sha256su1": 12,
    }
    if instruction_counts != expected_counts:
        raise BenchmarkError(
            "BoringSSL ARM64 SHA-256 hardware kernel instruction contract "
            "failed: "
            + json.dumps(
                {
                    "expected": expected_counts,
                    "actual": instruction_counts,
                },
                sort_keys=True,
            )
        )
    dispatch_evidence: dict[str, Any] = {}
    for label, symbol_fragment, required_calls in (
        (
            "update",
            "BCM_sha256_update",
            (
                ("bounded input copy", "_memcpy", 3),
                ("ARM64 hardware kernel", "_sha256_block_data_order_hw", 2),
                ("abort", "_abort", 1),
            ),
        ),
        (
            "final",
            "BCM_sha256_final",
            (
                ("state zero fill", "_bzero", 2),
                ("ARM64 hardware kernel", "_sha256_block_data_order_hw", 2),
                ("abort", "_abort", 1),
            ),
        ),
    ):
        dispatch = load_macho_text_function(
            path,
            toolchain=toolchain,
            required_symbol_fragments=(symbol_fragment,),
            label=f"BoringSSL SHA-256 {label} dispatch",
        )
        hardware_calls = [
            {
                "address": f"0x{address:x}",
                "instruction": instruction,
            }
            for address, instruction, _ in dispatch["instructions"]
            if is_call_instruction(instruction)
            and "_sha256_block_data_order_hw" in instruction
        ]
        software_calls = [
            instruction
            for _, instruction, _ in dispatch["instructions"]
            if is_call_instruction(instruction)
            and "_sha256_block_data_order_nohw" in instruction
        ]
        if not hardware_calls or software_calls:
            raise BenchmarkError(
                f"BoringSSL SHA-256 {label} dispatch must call the ARM64 "
                "hardware kernel and must not directly call the no-hardware "
                f"kernel; found {len(hardware_calls)} hardware and "
                f"{len(software_calls)} no-hardware calls"
            )
        direct_call_contract = validate_direct_call_contract(
            dispatch["instructions"],
            label=f"BoringSSL SHA-256 {label} dispatch",
            required_calls=required_calls,
        )
        dispatch_evidence[label] = {
            "symbol": dispatch["symbol"],
            "hardwareCalls": hardware_calls,
            "noHardwareDirectCallCount": len(software_calls),
            "directCalls": direct_call_contract,
        }

    public_call_contracts: dict[str, Any] = {}
    for label, exact_symbol, required_calls in (
        (
            "oneShot",
            "_SHA256",
            (
                ("BCM init", "BCM_sha256_init", 1),
                ("BCM update", "BCM_sha256_update", 1),
                ("BCM final", "BCM_sha256_final", 1),
                ("state cleanse", "_OPENSSL_cleanse", 1),
                ("stack-check failure", "stack_chk_fail", 1),
            ),
        ),
        (
            "update",
            "_SHA256_Update",
            (("BCM update", "BCM_sha256_update", 1),),
        ),
        (
            "final",
            "_SHA256_Final",
            (("BCM final", "BCM_sha256_final", 1),),
        ),
    ):
        public_function = load_macho_text_function(
            path,
            toolchain=toolchain,
            exact_symbol=exact_symbol,
            label=f"BoringSSL public SHA-256 {label}",
        )
        public_call_contracts[label] = {
            "symbol": public_function["symbol"],
            "directCalls": validate_direct_call_contract(
                public_function["instructions"],
                label=f"BoringSSL public SHA-256 {label}",
                required_calls=required_calls,
            ),
        }

    benchmark_main = load_macho_text_function(
        path,
        toolchain=toolchain,
        exact_symbol="_main",
        label="BoringSSL benchmark main",
    )
    main_instructions = benchmark_main["instructions"]
    clock_calls = [
        (address, instruction)
        for address, instruction, _ in main_instructions
        if is_call_instruction(instruction)
        and "steady_clock3nowEv" in instruction
    ]
    if len(clock_calls) != 2:
        raise BenchmarkError(
            "BoringSSL benchmark main must call the steady clock exactly "
            f"twice; found {len(clock_calls)}"
        )
    timed_start = clock_calls[0][0]
    timed_end = clock_calls[1][0]
    timed_instructions = [
        (address, instruction, line)
        for address, instruction, line in main_instructions
        if timed_start < address < timed_end
    ]
    timed_calls = [
        (address, instruction)
        for address, instruction, _ in timed_instructions
        if is_call_instruction(instruction)
    ]
    sha256_calls = [
        (address, instruction)
        for address, instruction in timed_calls
        if re.search(r"(?:^|\s)_SHA256$", instruction) is not None
    ]
    if len(timed_calls) != 1 or len(sha256_calls) != 1:
        raise BenchmarkError(
            "BoringSSL timed loop must call only the public SHA256 one-shot "
            f"function once; calls were {[item[1] for item in timed_calls]}"
        )
    main_backedges = find_backedges(
        main_instructions,
        function_start=benchmark_main["functionStart"],
    )
    timed_backedges = [
        (target, branch)
        for target, branch in main_backedges
        if timed_start < target <= branch < timed_end
    ]
    if len(timed_backedges) != 1:
        raise BenchmarkError(
            "BoringSSL timed region must contain exactly one loop backedge; "
            f"found {len(timed_backedges)}"
        )
    timed_loop_start, timed_loop_end = timed_backedges[0]
    sha256_call_address = sha256_calls[0][0]
    if not timed_loop_start <= sha256_call_address <= timed_loop_end:
        raise BenchmarkError(
            "BoringSSL public SHA256 call is outside the timed loop"
        )
    timed_external_transfers = [
        instruction
        for _, instruction, _ in timed_instructions
        if (
            is_external_branch_transfer(
                instruction=instruction,
                function_start=benchmark_main["functionStart"],
                function_end=benchmark_main["functionEnd"],
            )
            or is_return_instruction(instruction)
        )
    ]
    if timed_external_transfers:
        raise BenchmarkError(
            "BoringSSL timed region contains external branch transfers: "
            + ", ".join(timed_external_transfers)
        )
    return {
        "symbol": function["symbol"],
        "functionStartAddress": f"0x{function['functionStart']:x}",
        "functionEndAddress": f"0x{function['functionEnd']:x}",
        "instructionCounts": instruction_counts,
        "dispatch": dispatch_evidence,
        "publicCallContracts": public_call_contracts,
        "timedLoop": {
            "mainSymbol": benchmark_main["symbol"],
            "clockStartAddress": f"0x{timed_start:x}",
            "clockEndAddress": f"0x{timed_end:x}",
            "loopStartAddress": f"0x{timed_loop_start:x}",
            "loopBackedgeAddress": f"0x{timed_loop_end:x}",
            "sha256CallAddress": f"0x{sha256_call_address:x}",
            "externalBranchTransferCount": len(timed_external_transfers),
            "disassembly": "\n".join(
                line for _, _, line in timed_instructions
            ),
        },
        "passed": True,
    }


def collect_toolchain_metadata() -> dict[str, Any]:
    developer_directory = run_command(
        [XCODE_SELECT_EXECUTABLE, "-p"]
    ).stdout.strip()
    environment = sanitized_environment(
        {
            "DEVELOPER_DIR": developer_directory,
            "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
        }
    )
    xcrun_tools: dict[str, dict[str, Any]] = {}
    for tool in (
        "swift",
        "swiftc",
        "clang",
        "clang++",
        "nm",
        "otool",
        "lipo",
        "vtool",
    ):
        tool_path = run_command(
            [XCRUN_EXECUTABLE, "--find", tool],
            environment=environment,
        ).stdout.strip()
        xcrun_tools[tool] = executable_metadata(Path(tool_path))

    swift_driver = xcrun_tools["swift"]
    swift_compiler = xcrun_tools["swiftc"]
    clang_compiler = xcrun_tools["clang"]
    clangxx_compiler = xcrun_tools["clang++"]
    swift_version = run_command(
        [swift_driver["invocationPath"], "--version"],
        environment=environment,
        executable_path=swift_driver["path"],
    ).stdout.strip()
    if EXPECTED_SWIFT_COMPILER_COMMIT not in swift_version:
        raise BenchmarkError(
            "pinned Swift compiler commit was not found in `swift --version`: "
            f"expected {EXPECTED_SWIFT_COMPILER_COMMIT}"
        )

    clang_version = run_command(
        [clang_compiler["invocationPath"], "--version"],
        environment=environment,
        executable_path=clang_compiler["path"],
    ).stdout.strip()
    clang_resource_directory = Path(
        run_command(
            [clang_compiler["invocationPath"], "-print-resource-dir"],
            environment=environment,
            executable_path=clang_compiler["path"],
        ).stdout.strip()
    ).resolve()
    clang_toolchain_root = Path(clang_compiler["path"]).resolve().parents[2]
    try:
        clang_resource_directory.relative_to(clang_toolchain_root)
    except ValueError as error:
        raise BenchmarkError(
            "Clang resource directory is outside the pinned toolchain: "
            f"{clang_resource_directory}"
        ) from error
    if not clang_resource_directory.is_dir():
        raise BenchmarkError(
            "Clang resource directory does not exist: "
            f"{clang_resource_directory}"
        )
    sdk_path = run_command(
        [XCRUN_EXECUTABLE, "--sdk", "macosx", "--show-sdk-path"],
        environment=environment,
    ).stdout.strip()
    sdk_version = run_command(
        [XCRUN_EXECUTABLE, "--sdk", "macosx", "--show-sdk-version"],
        environment=environment,
    ).stdout.strip()
    sdk_build = run_command(
        [
            XCRUN_EXECUTABLE,
            "--sdk",
            "macosx",
            "--show-sdk-build-version",
        ],
        environment=environment,
    ).stdout.strip()
    xcode_version_output = run_command(
        [XCODEBUILD_EXECUTABLE, "-version"],
        environment=environment,
    ).stdout.strip()
    xcode_match = re.fullmatch(
        r"Xcode ([^\n]+)\nBuild version ([^\n]+)",
        xcode_version_output,
    )
    if xcode_match is None:
        raise BenchmarkError(
            f"unexpected `xcodebuild -version` output: {xcode_version_output}"
        )
    swift_target_match = re.search(r"^Target:\s+(.+)$", swift_version, re.MULTILINE)
    if swift_target_match is None:
        raise BenchmarkError("Swift compiler target was not reported")

    cmake_metadata = resolve_executable(
        label="CMake",
        candidates=CMAKE_EXECUTABLE_CANDIDATES,
    )
    cmake_metadata["version"] = run_command(
        [cmake_metadata["path"], "--version"],
        executable_path=cmake_metadata["path"],
    ).stdout.strip()
    ninja_metadata = resolve_executable(
        label="Ninja",
        candidates=NINJA_EXECUTABLE_CANDIDATES,
    )
    ninja_metadata["version"] = run_command(
        [ninja_metadata["path"], "--version"],
        executable_path=ninja_metadata["path"],
    ).stdout.strip()

    fixed_executable_paths = {
        "git": GIT_EXECUTABLE,
        "xcrun": XCRUN_EXECUTABLE,
        "xcodebuild": XCODEBUILD_EXECUTABLE,
        "xcode-select": XCODE_SELECT_EXECUTABLE,
        "tar": TAR_EXECUTABLE,
        "ps": PS_EXECUTABLE,
        "pmset": PMSET_EXECUTABLE,
        "sysctl": SYSCTL_EXECUTABLE,
        "sw_vers": SW_VERS_EXECUTABLE,
    }
    trusted_executables = {
        label: executable_metadata(Path(path))
        for label, path in fixed_executable_paths.items()
    }
    trusted_executables.update(
        {
            f"xcrun:{label}": metadata
            for label, metadata in xcrun_tools.items()
        }
    )
    trusted_executables["cmake"] = cmake_metadata
    trusted_executables["ninja"] = ninja_metadata
    verify_executable_metadata_unchanged(trusted_executables)
    return {
        "expectedIdentifier": EXPECTED_SWIFT_TOOLCHAIN,
        "expectedCompilerCommit": EXPECTED_SWIFT_COMPILER_COMMIT,
        "runnerEnvironmentIdentifier": os.environ.get("TOOLCHAINS"),
        "runnerArchitecture": platform.machine(),
        "expectedArchitecture": EXPECTED_ARCHITECTURE,
        "swiftBuildTriple": SWIFT_BUILD_TRIPLE,
        "swiftVersion": swift_version,
        "swiftDefaultTarget": swift_target_match.group(1),
        "clangVersion": clang_version,
        "clangResourceDirectory": str(clang_resource_directory),
        "swiftDriver": swift_driver,
        "swiftCompiler": swift_compiler["path"],
        "clangCompiler": clang_compiler["path"],
        "clangxxCompiler": clangxx_compiler["path"],
        "nm": xcrun_tools["nm"],
        "otool": xcrun_tools["otool"],
        "lipo": xcrun_tools["lipo"],
        "vtool": xcrun_tools["vtool"],
        "developerDirectory": developer_directory,
        "xcodeVersion": xcode_match.group(1),
        "xcodeBuild": xcode_match.group(2),
        "macOSSDKPath": sdk_path,
        "macOSSDKVersion": sdk_version,
        "macOSSDKBuild": sdk_build,
        "cmake": cmake_metadata,
        "ninja": ninja_metadata,
        "trustedExecutables": trusted_executables,
        "environmentPolicy": {
            "inheritedNames": sorted(INHERITED_ENVIRONMENT_NAMES),
            "fixedValues": FIXED_ENVIRONMENT,
            "buildOverrides": [
                "DEVELOPER_DIR",
                "SDKROOT",
                "SWIFT_SSL_ENABLE_BENCHMARKS",
                "TOOLCHAINS",
            ],
            "allOtherVariablesDiscarded": True,
            "effectiveBaseEnvironment": sanitized_environment(),
        },
    }


def is_build_process_name(name: str) -> bool:
    normalized = name.strip().strip("()")
    if normalized in BUILD_PROCESS_EXCLUDED_EXACT_NAMES:
        return False
    return (
        normalized in BUILD_PROCESS_EXACT_NAMES
        or any(
            normalized.startswith(prefix)
            for prefix in BUILD_PROCESS_PREFIXES
        )
    )


def active_build_processes() -> dict[str, int] | None:
    process_names = optional_command([PS_EXECUTABLE, "-axo", "comm="])
    if process_names is None:
        return None
    counts: dict[str, int] = {}
    for line in process_names.splitlines():
        name = Path(line.strip()).name.strip("()")
        if is_build_process_name(name):
            counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def power_mode() -> int | None:
    configuration = optional_command([PMSET_EXECUTABLE, "-g"])
    if configuration is None:
        return None
    values = [int(value, 10) for value in POWER_MODE_PATTERN.findall(configuration)]
    if not values:
        return None
    return values[-1]


def collect_quiescence() -> dict[str, Any]:
    logical_cpu_count = os.cpu_count()
    try:
        load_average = os.getloadavg()
    except OSError:
        load_average = None
    load_per_cpu = None
    if load_average is not None and logical_cpu_count:
        load_per_cpu = load_average[0] / logical_cpu_count
    power_state = optional_command([PMSET_EXECUTABLE, "-g", "batt"])
    thermal_state = optional_command([PMSET_EXECUTABLE, "-g", "therm"])
    return {
        "observedAt": utc_now(),
        "logicalCPUCount": logical_cpu_count,
        "loadAverage": list(load_average) if load_average is not None else None,
        "oneMinuteLoadPerLogicalCPU": load_per_cpu,
        "maximumLoadPerLogicalCPU": MAXIMUM_LOAD_PER_LOGICAL_CPU,
        "activeBuildProcesses": active_build_processes(),
        "buildProcessDetection": {
            "exactNames": sorted(BUILD_PROCESS_EXACT_NAMES),
            "prefixes": list(BUILD_PROCESS_PREFIXES),
            "excludedExactNames": sorted(
                BUILD_PROCESS_EXCLUDED_EXACT_NAMES
            ),
        },
        "powerState": power_state,
        "powerMode": power_mode(),
        "thermalState": thermal_state,
    }


def quiescence_reasons(observation: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    load_per_cpu = observation["oneMinuteLoadPerLogicalCPU"]
    if load_per_cpu is None:
        reasons.append("one-minute load per logical CPU is unavailable")
    elif load_per_cpu > MAXIMUM_LOAD_PER_LOGICAL_CPU:
        reasons.append(
            "one-minute load per logical CPU exceeds "
            f"{MAXIMUM_LOAD_PER_LOGICAL_CPU:.2f}: {load_per_cpu:.6f}"
        )
    build_processes = observation["activeBuildProcesses"]
    if build_processes is None:
        reasons.append("build process state is unavailable")
    elif build_processes:
        reasons.append(f"build processes are active: {build_processes}")
    power_state = observation["powerState"]
    if power_state is None or "AC Power" not in power_state:
        reasons.append("host is not verifiably drawing from AC power")
    if observation["powerMode"] is None:
        reasons.append("power mode state is unavailable")
    elif observation["powerMode"] == 1:
        reasons.append("Low Power Mode is enabled")
    thermal_state = observation["thermalState"]
    if thermal_state is None:
        reasons.append("thermal state is unavailable")
    elif (
        "No thermal warning level has been recorded" not in thermal_state
        or "No performance warning level has been recorded" not in thermal_state
    ):
        reasons.append("thermal or performance warning is present")
    return reasons


def collect_host_metadata() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "hardwareModel": optional_command(
            [SYSCTL_EXECUTABLE, "-n", "hw.model"]
        ),
        "pythonVersion": platform.python_version(),
        "logicalCPUCount": os.cpu_count(),
        "cpuBrand": optional_command(
            [SYSCTL_EXECUTABLE, "-n", "machdep.cpu.brand_string"]
        ),
        "sha256Feature": optional_command(
            [SYSCTL_EXECUTABLE, "-n", "hw.optional.arm.FEAT_SHA256"]
        ),
        "performanceCoreCount": optional_command(
            [SYSCTL_EXECUTABLE, "-n", "hw.perflevel0.physicalcpu"]
        ),
        "efficiencyCoreCount": optional_command(
            [SYSCTL_EXECUTABLE, "-n", "hw.perflevel1.physicalcpu"]
        ),
        "operatingSystem": optional_command([SW_VERS_EXECUTABLE]),
    }


def wait_for_quiescence(timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, Any]] = []
    while True:
        observation = collect_quiescence()
        observations.append(observation)
        reasons = quiescence_reasons(observation)
        if not reasons:
            return {
                "criterion": {
                    "maximumLoadPerLogicalCPU": MAXIMUM_LOAD_PER_LOGICAL_CPU,
                    "activeBuildProcesses": 0,
                    "buildProcessExactNames": sorted(
                        BUILD_PROCESS_EXACT_NAMES
                    ),
                    "buildProcessPrefixes": list(BUILD_PROCESS_PREFIXES),
                    "buildProcessExcludedExactNames": sorted(
                        BUILD_PROCESS_EXCLUDED_EXACT_NAMES
                    ),
                    "requiresACPower": True,
                    "requiresLowPowerModeDisabled": True,
                    "requiresNoThermalOrPerformanceWarning": True,
                },
                "observations": observations,
                "converged": True,
            }
        if time.monotonic() >= deadline:
            raise BenchmarkError(
                "host did not become quiescent before the timeout: "
                + "; ".join(reasons)
            )
        time.sleep(QUIESCENCE_POLL_SECONDS)


def validate_boringssl_repository(metadata: dict[str, Any]) -> None:
    if metadata["commit"] != EXPECTED_BORINGSSL_COMMIT:
        raise BenchmarkError(
            "BoringSSL commit mismatch: "
            f"expected {EXPECTED_BORINGSSL_COMMIT}, found {metadata['commit']}"
        )
    if not metadata["isClean"]:
        raise BenchmarkError("BoringSSL working tree must be clean")
    origin = normalize_boringssl_origin(metadata["origin"])
    if origin != EXPECTED_BORINGSSL_ORIGIN:
        raise BenchmarkError(
            "BoringSSL origin mismatch: "
            f"expected {EXPECTED_BORINGSSL_ORIGIN}, found {metadata['origin']}"
        )


def formal_eligibility_reasons(
    swift_repository: dict[str, Any],
    toolchain: dict[str, Any],
    quiescence: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if swift_repository["commit"] is None:
        reasons.append("swift-ssl has no committed HEAD")
    if not swift_repository["isClean"]:
        reasons.append("swift-ssl working tree is dirty")
    if toolchain["runnerEnvironmentIdentifier"] != EXPECTED_SWIFT_TOOLCHAIN:
        reasons.append(
            f"TOOLCHAINS is not set to {EXPECTED_SWIFT_TOOLCHAIN} for this run"
        )
    if toolchain["runnerArchitecture"] != EXPECTED_ARCHITECTURE:
        reasons.append(
            "benchmark runner architecture mismatch: "
            f"expected {EXPECTED_ARCHITECTURE}, "
            f"found {toolchain['runnerArchitecture']}"
        )
    if not toolchain["swiftDefaultTarget"].startswith(
        f"{EXPECTED_ARCHITECTURE}-apple-macosx"
    ):
        reasons.append(
            "Swift compiler default target is not native arm64 macOS: "
            f"{toolchain['swiftDefaultTarget']}"
        )
    if toolchain["xcodeVersion"] != EXPECTED_XCODE_VERSION:
        reasons.append(
            "Xcode version mismatch: "
            f"expected {EXPECTED_XCODE_VERSION}, "
            f"found {toolchain['xcodeVersion']}"
        )
    if toolchain["xcodeBuild"] != EXPECTED_XCODE_BUILD:
        reasons.append(
            "Xcode build mismatch: "
            f"expected {EXPECTED_XCODE_BUILD}, found {toolchain['xcodeBuild']}"
        )
    if toolchain["macOSSDKVersion"] != EXPECTED_MACOS_SDK_VERSION:
        reasons.append(
            "macOS SDK version mismatch: "
            f"expected {EXPECTED_MACOS_SDK_VERSION}, "
            f"found {toolchain['macOSSDKVersion']}"
        )
    if toolchain["macOSSDKBuild"] != EXPECTED_MACOS_SDK_BUILD:
        reasons.append(
            "macOS SDK build mismatch: "
            f"expected {EXPECTED_MACOS_SDK_BUILD}, "
            f"found {toolchain['macOSSDKBuild']}"
        )
    reasons.extend(quiescence_reasons(quiescence))
    return reasons


def default_output_path() -> Path:
    return SCRIPT_DIRECTORY / "Results" / f"{utc_file_timestamp()}-native-sha256.json"


def default_build_root() -> Path:
    return (
        REPOSITORY_ROOT
        / ".build"
        / "benchmark-sha256"
        / f"{utc_file_timestamp()}-{os.getpid()}"
    )


def collect_storage_capacity(
    paths: dict[str, Path],
) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for label, path in paths.items():
        resolved = path.expanduser().resolve()
        probe = resolved if resolved.is_dir() else resolved.parent
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        if not probe.is_dir():
            raise BenchmarkError(
                f"could not find an existing storage parent for {resolved}"
            )
        filesystem = os.statvfs(probe)
        observations[label] = {
            "requestedPath": str(resolved),
            "observedAtPath": str(probe),
            "device": os.stat(probe).st_dev,
            "availableBytes": filesystem.f_bavail * filesystem.f_frsize,
            "freeBytes": filesystem.f_bfree * filesystem.f_frsize,
            "totalBytes": filesystem.f_blocks * filesystem.f_frsize,
        }
    return observations


def require_available_storage(
    observations: dict[str, dict[str, Any]],
    *,
    minimum_available_bytes: int,
    phase: str,
) -> None:
    insufficient = {
        label: observation["availableBytes"]
        for label, observation in observations.items()
        if observation["availableBytes"] < minimum_available_bytes
    }
    if insufficient:
        raise BenchmarkError(
            f"insufficient storage during {phase}; required "
            f"{minimum_available_bytes} available bytes: "
            + json.dumps(insufficient, sort_keys=True)
        )


def prepare_build_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.exists():
        raise BenchmarkError(f"fresh build root already exists: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.mkdir()
    return resolved


def make_tree_read_only(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        current_mode = path.stat().st_mode
        if path.is_dir():
            path.chmod(0o555)
        elif path.is_file():
            executable = bool(
                current_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            )
            path.chmod(0o555 if executable else 0o444)
    root.chmod(0o555)


def reject_source_snapshot_symlinks(root: Path) -> dict[str, Any]:
    symlinks = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_symlink()
    ]
    if symlinks:
        raise BenchmarkError(
            "formal source snapshots must not contain symlinks: "
            + ", ".join(symlinks)
        )
    return {
        "policy": "reject all symlinks",
        "symlinkCount": 0,
        "passed": True,
    }


def directory_manifest_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        path_stat = path.lstat()
        mode = stat.S_IMODE(path_stat.st_mode)
        if path.is_symlink():
            kind = "symlink"
            content_digest = hashlib.sha256(
                os.readlink(path).encode("utf-8")
            ).hexdigest()
        elif path.is_dir():
            kind = "directory"
            content_digest = "-"
        elif path.is_file():
            kind = "file"
            content_digest = file_sha256(path)
        else:
            raise BenchmarkError(f"unsupported source snapshot entry: {path}")
        record = (
            f"{kind}\0{mode:o}\0{path_stat.st_size}\0{relative}\0"
            f"{content_digest}\n"
        )
        digest.update(record.encode("utf-8"))
    return digest.hexdigest()


def create_git_archive_snapshot(
    *,
    label: str,
    repository: Path,
    commit: str,
    tree: str,
    snapshot_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    archive_path = snapshot_root / f"{label}.tar"
    source_path = snapshot_root / label
    archive_command = [
        GIT_EXECUTABLE,
        "-C",
        str(repository),
        "archive",
        "--format=tar",
        commit,
    ]
    archive_evidence = run_command_to_file(
        archive_command,
        cwd=REPOSITORY_ROOT,
        output_path=archive_path,
        timeout_seconds=timeout_seconds,
    )
    source_path.mkdir()
    extract_command = [
        TAR_EXECUTABLE,
        "-xf",
        str(archive_path),
        "-C",
        str(source_path),
    ]
    extract_completed = run_command(
        extract_command,
        cwd=REPOSITORY_ROOT,
        timeout_seconds=timeout_seconds,
    )
    symlink_validation = reject_source_snapshot_symlinks(source_path)
    make_tree_read_only(source_path)
    archive_path.chmod(0o444)
    content_manifest_sha256 = directory_manifest_sha256(source_path)
    return {
        "repository": str(repository),
        "commit": commit,
        "tree": tree,
        "archive": {
            "path": str(archive_path),
            "sha256": file_sha256(archive_path),
            "sizeBytes": archive_path.stat().st_size,
            "creation": archive_evidence,
        },
        "extraction": {
            "command": extract_command,
            "environment": sanitized_environment(),
            "returnCode": extract_completed.returncode,
            "stderr": extract_completed.stderr,
        },
        "sourcePath": str(source_path),
        "contentManifestSHA256": content_manifest_sha256,
        "symlinkValidation": symlink_validation,
        "readOnly": True,
    }


def create_formal_source_snapshots(
    *,
    build_root: Path,
    swift_repository: dict[str, Any],
    boringssl_repository: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    swift_commit = swift_repository["commit"]
    boringssl_commit = boringssl_repository["commit"]
    if swift_commit is None or boringssl_commit is None:
        raise BenchmarkError("formal source snapshots require committed HEADs")

    swift_tree = git_value(REPOSITORY_ROOT, ["rev-parse", f"{swift_commit}^{{tree}}"])
    boringssl_path = Path(boringssl_repository["path"])
    boringssl_tree = git_value(
        boringssl_path,
        ["rev-parse", f"{boringssl_commit}^{{tree}}"],
    )
    if swift_tree is None or boringssl_tree is None:
        raise BenchmarkError("could not resolve source tree identifiers")

    snapshot_root = build_root / "source-snapshots"
    snapshot_root.mkdir()
    swift_snapshot = create_git_archive_snapshot(
        label="swift-ssl",
        repository=REPOSITORY_ROOT,
        commit=swift_commit,
        tree=swift_tree,
        snapshot_root=snapshot_root,
        timeout_seconds=timeout_seconds,
    )
    boringssl_snapshot = create_git_archive_snapshot(
        label="boringssl",
        repository=boringssl_path,
        commit=boringssl_commit,
        tree=boringssl_tree,
        snapshot_root=snapshot_root,
        timeout_seconds=timeout_seconds,
    )
    return {
        "mode": "read-only git archives",
        "ssl": swift_snapshot,
        "boringSSL": boringssl_snapshot,
    }


def verify_formal_source_snapshots_unchanged(
    snapshots: dict[str, Any],
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for key in ("ssl", "boringSSL"):
        snapshot = snapshots[key]
        archive_path = Path(snapshot["archive"]["path"])
        source_path = Path(snapshot["sourcePath"])
        final_archive_sha256 = file_sha256(archive_path)
        final_manifest_sha256 = directory_manifest_sha256(source_path)
        if final_archive_sha256 != snapshot["archive"]["sha256"]:
            raise BenchmarkError(f"{key} source archive changed during benchmark")
        if final_manifest_sha256 != snapshot["contentManifestSHA256"]:
            raise BenchmarkError(
                f"{key} source snapshot changed during benchmark"
            )
        results[key] = {
            "archiveSHA256": final_archive_sha256,
            "contentManifestSHA256": final_manifest_sha256,
            "unchanged": True,
        }
    return results


def build_workers(
    *,
    build_root: Path,
    swift_source: Path,
    boringssl_source: Path,
    boringssl_commit: str,
    toolchain: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    verify_executable_metadata_unchanged(toolchain["trustedExecutables"])
    selected_environment = {
        "DEVELOPER_DIR": toolchain["developerDirectory"],
        "SDKROOT": toolchain["macOSSDKPath"],
        "SWIFT_SSL_ENABLE_BENCHMARKS": "1",
        "TOOLCHAINS": EXPECTED_SWIFT_TOOLCHAIN,
    }
    environment = sanitized_environment(selected_environment)

    swift_scratch = build_root / "swift"
    swift_cache = build_root / "swift-cache"
    swift_command = [
        toolchain["swiftDriver"]["invocationPath"],
        "build",
        "--build-system",
        "native",
        "--disable-dependency-cache",
        "--disable-build-manifest-caching",
        "--cache-path",
        str(swift_cache),
        "--configuration",
        "release",
        "--product",
        "swift-ssl-sha256-benchmark",
        "--scratch-path",
        str(swift_scratch),
        "--triple",
        SWIFT_BUILD_TRIPLE,
        "--sdk",
        toolchain["macOSSDKPath"],
        "--jobs",
        "2",
        "-v",
    ]
    swift_completed = run_command(
        swift_command,
        cwd=swift_source,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=toolchain["swiftDriver"]["path"],
    )
    show_bin_path_command = [
        toolchain["swiftDriver"]["invocationPath"],
        "build",
        "--build-system",
        "native",
        "--disable-dependency-cache",
        "--disable-build-manifest-caching",
        "--cache-path",
        str(swift_cache),
        "--configuration",
        "release",
        "--scratch-path",
        str(swift_scratch),
        "--triple",
        SWIFT_BUILD_TRIPLE,
        "--sdk",
        toolchain["macOSSDKPath"],
        "--show-bin-path",
    ]
    show_bin_path_completed = run_command(
        show_bin_path_command,
        cwd=swift_source,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=toolchain["swiftDriver"]["path"],
    )
    bin_path_lines = [
        line.strip()
        for line in show_bin_path_completed.stdout.splitlines()
        if line.strip()
    ]
    if not bin_path_lines:
        raise BenchmarkError("SwiftPM did not report a binary path")
    swift_worker = (
        Path(bin_path_lines[-1]).resolve() / "swift-ssl-sha256-benchmark"
    )

    boringssl_build = build_root / "boringssl"
    configure_command = [
        toolchain["cmake"]["path"],
        "-S",
        str(swift_source / "Benchmarks/SHA256/BoringSSLDriver"),
        "-B",
        str(boringssl_build),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_OSX_ARCHITECTURES={EXPECTED_ARCHITECTURE}",
        f"-DCMAKE_OSX_DEPLOYMENT_TARGET={DEPLOYMENT_TARGET}",
        f"-DCMAKE_OSX_SYSROOT={toolchain['macOSSDKPath']}",
        f"-DCMAKE_C_COMPILER={toolchain['clangCompiler']}",
        f"-DCMAKE_CXX_COMPILER={toolchain['clangxxCompiler']}",
        "-DCMAKE_CXX_COMPILER_ARG1=--driver-mode=g++",
        f"-DCMAKE_ASM_COMPILER={toolchain['clangCompiler']}",
        f"-DCMAKE_MAKE_PROGRAM={toolchain['ninja']['path']}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DBORINGSSL_SOURCE={boringssl_source}",
        f"-DBORINGSSL_COMMIT={boringssl_commit}",
    ]
    configure_completed = run_command(
        configure_command,
        cwd=swift_source,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=toolchain["cmake"]["path"],
    )
    boringssl_build_command = [
        toolchain["cmake"]["path"],
        "--build",
        str(boringssl_build),
        "--target",
        "boringssl-sha256-benchmark",
        "--parallel",
        "2",
        "--verbose",
    ]
    boringssl_build_completed = run_command(
        boringssl_build_command,
        cwd=build_root,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=toolchain["cmake"]["path"],
    )
    boringssl_worker = boringssl_build / "boringssl-sha256-benchmark"

    compile_database_path = boringssl_build / "compile_commands.json"
    cmake_cache_path = boringssl_build / "CMakeCache.txt"
    if not compile_database_path.is_file():
        raise BenchmarkError("BoringSSL compile database was not generated")
    if not cmake_cache_path.is_file():
        raise BenchmarkError("BoringSSL CMake cache was not generated")

    compile_database = json.loads(
        compile_database_path.read_text(encoding="utf-8")
    )
    if not isinstance(compile_database, list):
        raise BenchmarkError("BoringSSL compile database root must be an array")
    cmake_cache = cmake_cache_path.read_text(encoding="utf-8")
    swift_worker_metadata = executable_metadata(swift_worker)
    swift_worker_metadata["machO"] = collect_macho_metadata(
        swift_worker,
        toolchain=toolchain,
    )
    boringssl_worker_metadata = executable_metadata(boringssl_worker)
    boringssl_worker_metadata["machO"] = collect_macho_metadata(
        boringssl_worker,
        toolchain=toolchain,
    )
    swift_build_contract = require_swift_build_contract(
        completed=swift_completed,
        toolchain=toolchain,
        swift_source=swift_source,
        swift_scratch=swift_scratch,
    )
    boringssl_build_contract = require_boringssl_build_contract(
        compile_database=compile_database,
        cmake_cache=cmake_cache,
        toolchain=toolchain,
        swift_source=swift_source,
        boringssl_source=boringssl_source,
        boringssl_build=boringssl_build,
    )
    dependency_command = [
        toolchain["ninja"]["invocationPath"],
        "-C",
        str(boringssl_build),
        "-t",
        "deps",
    ]
    dependency_completed = run_command(
        dependency_command,
        cwd=build_root,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=toolchain["ninja"]["path"],
    )
    boringssl_dependency_contract = require_boringssl_dependency_contract(
        completed=dependency_completed,
        build_directory=boringssl_build,
        compile_outputs=boringssl_build_contract[
            "validatedCompileOutputs"
        ],
        required_object_outputs=boringssl_build_contract[
            "validatedRequiredObjectOutputs"
        ],
        boringssl_source=boringssl_source,
        driver_source=(
            swift_source
            / "Benchmarks/SHA256/BoringSSLDriver/SHA256Benchmark.cpp"
        ),
        sdk_root=Path(toolchain["macOSSDKPath"]),
        clang_resource_directory=Path(
            toolchain["clangResourceDirectory"]
        ),
    )
    boringssl_dependency_contract.update(
        {
            "command": dependency_command,
            "cwd": str(build_root),
            "environment": environment,
            "resolvedExecutablePath": toolchain["ninja"]["path"],
            "returnCode": dependency_completed.returncode,
            "stderr": dependency_completed.stderr,
        }
    )
    boringssl_link_contract = require_boringssl_link_contract(
        completed=boringssl_build_completed,
        build_directory=boringssl_build,
        toolchain=toolchain,
    )
    swift_codegen = analyze_swift_worker_codegen(
        swift_worker,
        toolchain=toolchain,
    )
    sha256_multiblock_codegen = analyze_sha256_multiblock_codegen(
        swift_worker,
        toolchain=toolchain,
    )
    boringssl_sha256_codegen = analyze_boringssl_sha256_backend_codegen(
        boringssl_worker,
        toolchain=toolchain,
    )
    boringssl_runtime_capability = validate_boringssl_runtime_capability(
        boringssl_worker,
        timeout_seconds=timeout_seconds,
    )
    return {
        "buildRoot": str(build_root),
        "freshBuildRoot": True,
        "sourcePaths": {
            "ssl": str(swift_source),
            "boringSSL": str(boringssl_source),
        },
        "swift": {
            "buildSystem": "native",
            "buildSystemRationale": (
                "The fixed SwiftBuild snapshot rewrites the final linked SDK "
                "load command to 15.0; the native SwiftPM build preserves the "
                "requested SDK 27.0 and is machine-code validated."
            ),
            "build": command_evidence(
                swift_command,
                cwd=swift_source,
                environment=environment,
                completed=swift_completed,
                executable_path=toolchain["swiftDriver"]["path"],
            ),
            "showBinPath": command_evidence(
                show_bin_path_command,
                cwd=swift_source,
                environment=environment,
                completed=show_bin_path_completed,
                executable_path=toolchain["swiftDriver"]["path"],
            ),
            "buildContract": swift_build_contract,
            "timedLoopCodeGeneration": swift_codegen,
            "sha256MultiBlockCodeGeneration": sha256_multiblock_codegen,
            "worker": swift_worker_metadata,
        },
        "boringSSL": {
            "configure": command_evidence(
                configure_command,
                cwd=swift_source,
                environment=environment,
                completed=configure_completed,
                executable_path=toolchain["cmake"]["path"],
            ),
            "build": command_evidence(
                boringssl_build_command,
                cwd=build_root,
                environment=environment,
                completed=boringssl_build_completed,
                executable_path=toolchain["cmake"]["path"],
            ),
            "compileDatabase": {
                "path": str(compile_database_path),
                "sha256": file_sha256(compile_database_path),
                "entries": compile_database,
            },
            "cmakeCache": {
                "path": str(cmake_cache_path),
                "sha256": file_sha256(cmake_cache_path),
                "content": cmake_cache,
            },
            "buildContract": boringssl_build_contract,
            "dependencyContract": boringssl_dependency_contract,
            "linkContract": boringssl_link_contract,
            "sha256BackendCodeGeneration": boringssl_sha256_codegen,
            "runtimeCapability": boringssl_runtime_capability,
            "worker": boringssl_worker_metadata,
        },
    }


def validate_boringssl_runtime_capability(
    executable: Path,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = [str(executable), "--capabilities"]
    environment = sanitized_environment()
    completed = run_command(
        command,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=str(executable),
    )
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise BenchmarkError(
            "BoringSSL capability probe must emit exactly one line"
        )
    if completed.stderr:
        raise BenchmarkError(
            "BoringSSL capability probe emitted unexpected stderr"
        )
    match = BORINGSSL_CAPABILITY_PATTERN.fullmatch(lines[0])
    if match is None or match.group(1) != "1":
        raise BenchmarkError(
            "BoringSSL capability probe did not confirm assembly: "
            + lines[0]
        )
    return {
        "command": command,
        "resolvedExecutablePath": str(executable),
        "environment": environment,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "assemblyEnabled": True,
        "passed": True,
    }


def run_worker(
    executable: Path,
    *,
    byte_count: int,
    iterations: int,
    warmup_iterations: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = [
        str(executable),
        str(byte_count),
        str(iterations),
        str(warmup_iterations),
    ]
    environment = sanitized_environment()
    wall_start = time.monotonic_ns()
    completed = run_command(
        command,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=str(executable),
    )
    wall_nanoseconds = time.monotonic_ns() - wall_start

    result_lines = completed.stdout.splitlines()
    if len(result_lines) != 1:
        raise BenchmarkError(
            f"worker must emit exactly one RESULT line: {' '.join(command)}"
        )
    if completed.stderr:
        raise BenchmarkError(
            f"worker emitted unexpected stderr: {' '.join(command)}"
        )
    match = RESULT_PATTERN.fullmatch(result_lines[0])
    if match is None:
        raise BenchmarkError(f"malformed worker RESULT line: {result_lines[0]}")

    measured_nanoseconds = int(match.group(1), 10)
    checksum = int(match.group(2), 10)
    if measured_nanoseconds <= 0:
        raise BenchmarkError("worker reported a nonpositive measured duration")
    if checksum > (1 << 64) - 1:
        raise BenchmarkError("worker checksum is outside the UInt64 range")

    return {
        "command": command,
        "environment": environment,
        "measuredNanoseconds": measured_nanoseconds,
        "wallNanoseconds": wall_nanoseconds,
        "checksum": checksum,
        "digestHex": match.group(3),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_validation_worker(
    executable: Path,
    *,
    byte_count: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    command = [
        str(executable),
        "--validate",
        str(byte_count),
        str(VALIDATION_ITERATION_COUNT),
    ]
    environment = sanitized_environment()
    wall_start = time.monotonic_ns()
    completed = run_command(
        command,
        timeout_seconds=timeout_seconds,
        environment=environment,
        executable_path=str(executable),
    )
    wall_nanoseconds = time.monotonic_ns() - wall_start

    if completed.stderr:
        raise BenchmarkError(
            f"validation worker emitted unexpected stderr: {' '.join(command)}"
        )
    digests: list[str] = []
    for expected_index, line in enumerate(completed.stdout.splitlines()):
        match = DIGEST_PATTERN.fullmatch(line)
        if match is None:
            raise BenchmarkError(
                f"malformed validation output from {' '.join(command)}: {line}"
            )
        actual_index = int(match.group(1), 10)
        if actual_index != expected_index:
            raise BenchmarkError(
                "validation iteration sequence mismatch: "
                f"expected {expected_index}, found {actual_index}"
            )
        digests.append(match.group(2))
    if len(digests) != VALIDATION_ITERATION_COUNT:
        raise BenchmarkError(
            "validation digest count mismatch: "
            f"expected {VALIDATION_ITERATION_COUNT}, found {len(digests)}"
        )
    return {
        "command": command,
        "environment": environment,
        "wallNanoseconds": wall_nanoseconds,
        "digests": digests,
        "stderr": completed.stderr,
    }


def validate_full_outputs(
    swift_worker: Path,
    boringssl_worker: Path,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    workloads: list[dict[str, Any]] = []
    for byte_count in HEADLINE_BYTE_COUNTS:
        swift = run_validation_worker(
            swift_worker,
            byte_count=byte_count,
            timeout_seconds=timeout_seconds,
        )
        boringssl = run_validation_worker(
            boringssl_worker,
            byte_count=byte_count,
            timeout_seconds=timeout_seconds,
        )
        if swift["digests"] != boringssl["digests"]:
            mismatch = next(
                (
                    index
                    for index, (swift_digest, boringssl_digest) in enumerate(
                        zip(swift["digests"], boringssl["digests"], strict=True)
                    )
                    if swift_digest != boringssl_digest
                ),
                None,
            )
            raise BenchmarkError(
                f"full digest validation mismatch at {byte_count} bytes, "
                f"iteration {mismatch}"
            )
        workloads.append(
            {
                "byteCount": byte_count,
                "iterationCount": VALIDATION_ITERATION_COUNT,
                "swiftCommand": swift["command"],
                "boringSSLCommand": boringssl["command"],
                "swiftWallNanoseconds": swift["wallNanoseconds"],
                "boringSSLWallNanoseconds": boringssl["wallNanoseconds"],
                "matchedDigests": swift["digests"],
            }
        )
    return {
        "placement": "outside all timed samples",
        "coverage": (
            "all 256 possible low-byte mutations for each headline input size"
        ),
        "allDigestsMatched": True,
        "workloads": workloads,
    }


def output_identity(result: dict[str, Any]) -> tuple[int, str]:
    return result["checksum"], result["digestHex"]


def require_matching_outputs(
    swift_result: dict[str, Any],
    boringssl_result: dict[str, Any],
    *,
    context: str,
) -> tuple[int, str]:
    swift_identity = output_identity(swift_result)
    boringssl_identity = output_identity(boringssl_result)
    if swift_identity != boringssl_identity:
        raise BenchmarkError(
            f"output mismatch in {context}: Swift {swift_identity}, "
            f"BoringSSL {boringssl_identity}"
        )
    return swift_identity


def warmup_iterations_for(iterations: int) -> int:
    return max(1_000, min(iterations // 10, 100_000))


def calibrate_iterations(
    swift_worker: Path,
    boringssl_worker: Path,
    *,
    byte_count: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    iterations = INITIAL_ITERATIONS[byte_count]
    rounds: list[dict[str, Any]] = []
    for round_index in range(MAXIMUM_CALIBRATION_ROUNDS):
        warmup_iterations = warmup_iterations_for(iterations)
        swift = run_worker(
            swift_worker,
            byte_count=byte_count,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            timeout_seconds=timeout_seconds,
        )
        boringssl = run_worker(
            boringssl_worker,
            byte_count=byte_count,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            timeout_seconds=timeout_seconds,
        )
        require_matching_outputs(
            swift,
            boringssl,
            context=f"{byte_count}-byte calibration round {round_index}",
        )
        minimum_duration = min(
            swift["measuredNanoseconds"],
            boringssl["measuredNanoseconds"],
        )
        rounds.append(
            {
                "round": round_index,
                "iterations": iterations,
                "warmupIterations": warmup_iterations,
                "swift": swift,
                "boringSSL": boringssl,
                "minimumMeasuredNanoseconds": minimum_duration,
            }
        )
        if minimum_duration >= MINIMUM_SAMPLE_NANOSECONDS:
            return {
                "criterion": {
                    "minimumMeasuredNanosecondsForBothWorkers": (
                        MINIMUM_SAMPLE_NANOSECONDS
                    ),
                    "maximumRounds": MAXIMUM_CALIBRATION_ROUNDS,
                },
                "rounds": rounds,
                "iterationsPerSample": iterations,
                "warmupIterationsPerInvocation": warmup_iterations,
                "converged": True,
            }

        scale = max(
            2,
            math.ceil(
                MINIMUM_SAMPLE_NANOSECONDS
                / minimum_duration
                * 1.10
            ),
        )
        next_iterations = iterations * scale
        if next_iterations > MAXIMUM_ITERATIONS:
            raise BenchmarkError(
                f"calibration for {byte_count} bytes exceeded the iteration limit"
            )
        iterations = next_iterations

    raise BenchmarkError(
        f"calibration for {byte_count} bytes did not reach the duration criterion"
    )


def duration_window_converged(values: Sequence[float]) -> bool:
    if len(values) < CONVERGENCE_WINDOW:
        return False
    window = values[-CONVERGENCE_WINDOW:]
    median = statistics.median(window)
    return all(
        abs(value - median) / median <= CONVERGENCE_TOLERANCE for value in window
    )


def verify_timing_convergence(
    swift_worker: Path,
    boringssl_worker: Path,
    *,
    byte_count: int,
    iterations: int,
    warmup_iterations: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    rounds: list[dict[str, Any]] = []
    swift_per_operation: list[float] = []
    boringssl_per_operation: list[float] = []
    for round_index in range(MAXIMUM_CONVERGENCE_ROUNDS):
        quiescence = collect_quiescence()
        reasons = quiescence_reasons(quiescence)
        if reasons:
            raise BenchmarkError(
                f"host failed quiescence before convergence round {round_index}: "
                + "; ".join(reasons)
            )

        order = (
            "swift-boringssl"
            if round_index % 2 == 0
            else "boringssl-swift"
        )
        implementations: tuple[tuple[str, Path], ...] = (
            ("swift", swift_worker),
            ("boringSSL", boringssl_worker),
        )
        if order == "boringssl-swift":
            implementations = tuple(reversed(implementations))
        results: dict[str, dict[str, Any]] = {}
        for implementation, executable in implementations:
            results[implementation] = run_worker(
                executable,
                byte_count=byte_count,
                iterations=iterations,
                warmup_iterations=warmup_iterations,
                timeout_seconds=timeout_seconds,
            )
        require_matching_outputs(
            results["swift"],
            results["boringSSL"],
            context=f"{byte_count}-byte convergence round {round_index}",
        )
        swift_per_operation.append(
            results["swift"]["measuredNanoseconds"] / iterations
        )
        boringssl_per_operation.append(
            results["boringSSL"]["measuredNanoseconds"] / iterations
        )
        rounds.append(
            {
                "round": round_index,
                "order": order,
                "quiescence": quiescence,
                "swift": results["swift"],
                "boringSSL": results["boringSSL"],
            }
        )
        if duration_window_converged(
            swift_per_operation
        ) and duration_window_converged(boringssl_per_operation):
            return {
                "criterion": {
                    "windowSize": CONVERGENCE_WINDOW,
                    "relativeDeviationFromWindowMedian": CONVERGENCE_TOLERANCE,
                    "maximumRounds": MAXIMUM_CONVERGENCE_ROUNDS,
                },
                "rounds": rounds,
                "converged": True,
            }

    raise BenchmarkError(
        f"timing did not converge for the {byte_count}-byte workload"
    )


def balanced_orders(sample_count: int, generator: random.Random) -> list[str]:
    orders = ["swift-boringssl"] * (sample_count // 2)
    orders.extend(["boringssl-swift"] * (sample_count // 2))
    if sample_count % 2 == 1:
        orders.append(generator.choice(["swift-boringssl", "boringssl-swift"]))
    generator.shuffle(orders)
    return orders


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise BenchmarkError("cannot calculate a percentile from no samples")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(ordered) - 1)
    fraction = position - lower_index
    return ordered[lower_index] + (
        ordered[upper_index] - ordered[lower_index]
    ) * fraction


def summarize_implementation(
    measured_nanoseconds: Sequence[int],
    *,
    byte_count: int,
    iterations: int,
) -> dict[str, Any]:
    batch_values = [float(value) for value in measured_nanoseconds]
    operation_values = [value / iterations for value in batch_values]
    total_bytes = byte_count * iterations
    throughput_values = [
        total_bytes * 1_000_000_000.0 / value for value in batch_values
    ]
    operations_per_second = [
        iterations * 1_000_000_000.0 / value for value in batch_values
    ]
    return {
        "batchNanoseconds": {
            "median": statistics.median(batch_values),
            "p95": percentile(batch_values, 0.95),
            "minimum": min(batch_values),
            "maximum": max(batch_values),
        },
        "nanosecondsPerOperation": {
            "median": statistics.median(operation_values),
            "p95": percentile(operation_values, 0.95),
        },
        "bytesPerSecond": {
            "median": statistics.median(throughput_values),
            "p05": percentile(throughput_values, 0.05),
            "p95": percentile(throughput_values, 0.95),
        },
        "operationsPerSecond": {
            "median": statistics.median(operations_per_second),
            "p05": percentile(operations_per_second, 0.05),
            "p95": percentile(operations_per_second, 0.95),
        },
    }


def paired_bootstrap_interval(
    paired_speedups: Sequence[float],
    *,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    generator = random.Random(seed)
    count = len(paired_speedups)
    bootstrap_medians: list[float] = []
    for _ in range(resamples):
        resampled = [
            paired_speedups[generator.randrange(count)] for _ in range(count)
        ]
        bootstrap_medians.append(statistics.median(resampled))
    return {
        "method": "paired-percentile-bootstrap-of-median-speedup",
        "confidenceLevel": 0.95,
        "resamples": resamples,
        "seed": seed,
        "lower": percentile(bootstrap_medians, 0.025),
        "upper": percentile(bootstrap_medians, 0.975),
    }


def target_decision(confidence_interval: dict[str, Any]) -> str:
    if confidence_interval["lower"] >= TARGET_SPEEDUP:
        return "pass"
    if confidence_interval["upper"] < TARGET_SPEEDUP:
        return "fail"
    return "inconclusive"


def sample_workload(
    swift_worker: Path,
    boringssl_worker: Path,
    *,
    byte_count: int,
    iterations: int,
    warmup_iterations: int,
    sample_count: int,
    bootstrap_resamples: int,
    seed: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    generator = random.Random(seed)
    orders = balanced_orders(sample_count, generator)
    samples: list[dict[str, Any]] = []
    expected_identity: tuple[int, str] | None = None

    for pair_index, order in enumerate(orders):
        quiescence = collect_quiescence()
        reasons = quiescence_reasons(quiescence)
        if reasons:
            raise BenchmarkError(
                f"host failed quiescence before sample pair {pair_index}: "
                + "; ".join(reasons)
            )

        implementations: tuple[tuple[str, Path], ...] = (
            ("swift", swift_worker),
            ("boringSSL", boringssl_worker),
        )
        if order == "boringssl-swift":
            implementations = tuple(reversed(implementations))

        results: dict[str, dict[str, Any]] = {}
        for implementation, executable in implementations:
            results[implementation] = run_worker(
                executable,
                byte_count=byte_count,
                iterations=iterations,
                warmup_iterations=warmup_iterations,
                timeout_seconds=timeout_seconds,
            )

        identity = require_matching_outputs(
            results["swift"],
            results["boringSSL"],
            context=f"{byte_count}-byte paired sample {pair_index}",
        )
        if expected_identity is None:
            expected_identity = identity
        elif identity != expected_identity:
            raise BenchmarkError(
                f"nondeterministic output in {byte_count}-byte pair {pair_index}: "
                f"expected {expected_identity}, found {identity}"
            )

        speedup = (
            results["boringSSL"]["measuredNanoseconds"]
            / results["swift"]["measuredNanoseconds"]
        )
        samples.append(
            {
                "pairIndex": pair_index,
                "order": order,
                "quiescence": quiescence,
                "swift": results["swift"],
                "boringSSL": results["boringSSL"],
                "pairedSpeedup": speedup,
            }
        )

    swift_nanoseconds = [
        sample["swift"]["measuredNanoseconds"] for sample in samples
    ]
    boringssl_nanoseconds = [
        sample["boringSSL"]["measuredNanoseconds"] for sample in samples
    ]
    paired_speedups = [sample["pairedSpeedup"] for sample in samples]
    bootstrap_seed = seed ^ 0x534841323536
    confidence_interval = paired_bootstrap_interval(
        paired_speedups,
        resamples=bootstrap_resamples,
        seed=bootstrap_seed,
    )
    swift_summary = summarize_implementation(
        swift_nanoseconds,
        byte_count=byte_count,
        iterations=iterations,
    )
    boringssl_summary = summarize_implementation(
        boringssl_nanoseconds,
        byte_count=byte_count,
        iterations=iterations,
    )
    ratio_of_median_throughputs = (
        swift_summary["bytesPerSecond"]["median"]
        / boringssl_summary["bytesPerSecond"]["median"]
    )
    return {
        "byteCount": byte_count,
        "iterationsPerSample": iterations,
        "warmupIterationsPerInvocation": warmup_iterations,
        "sampling": {
            "design": "balanced randomized paired AB-BA",
            "orderSeed": seed,
            "orders": orders,
            "samples": samples,
        },
        "statistics": {
            "swift": swift_summary,
            "boringSSL": boringssl_summary,
            "pairedSpeedup": {
                "definition": "BoringSSL elapsed time / Pure Swift elapsed time",
                "median": statistics.median(paired_speedups),
                "p05": percentile(paired_speedups, 0.05),
                "p95": percentile(paired_speedups, 0.95),
                "ratioOfMedianThroughputs": ratio_of_median_throughputs,
                "confidenceInterval95": confidence_interval,
            },
        },
        "target": {
            "minimumSpeedup": TARGET_SPEEDUP,
            "criterion": (
                "lower bound of the paired median speedup 95% bootstrap "
                "confidence interval is at least 1.10"
            ),
            "decision": target_decision(confidence_interval),
        },
        "matchedTimedOutput": {
            "checksum": expected_identity[0] if expected_identity else None,
            "digestHex": expected_identity[1] if expected_identity else None,
        },
    }


def overall_decision(workloads: Sequence[dict[str, Any]]) -> str:
    decisions = [workload["target"]["decision"] for workload in workloads]
    if all(decision == "pass" for decision in decisions):
        return "pass"
    if any(decision == "fail" for decision in decisions):
        return "fail"
    return "inconclusive"


def verify_repository_unchanged(
    *,
    label: str,
    initial: dict[str, Any],
    final: dict[str, Any],
    formal: bool,
) -> None:
    if initial["commit"] != final["commit"]:
        raise BenchmarkError(
            f"{label} HEAD changed during the benchmark: "
            f"{initial['commit']} -> {final['commit']}"
        )
    if normalize_boringssl_origin(
        initial["origin"]
    ) != normalize_boringssl_origin(final["origin"]):
        raise BenchmarkError(f"{label} origin changed during the benchmark")
    if formal and not final["isClean"]:
        raise BenchmarkError(f"{label} became dirty during the formal benchmark")


def verify_executable_unchanged(
    *,
    label: str,
    initial: dict[str, Any],
    final: dict[str, Any],
) -> None:
    if initial["sha256"] != final["sha256"]:
        raise BenchmarkError(f"{label} worker changed during the benchmark")


def verify_dependency_content_manifest_unchanged(
    dependency_contract: dict[str, Any],
) -> dict[str, Any]:
    dependency_files = [
        Path(path).resolve()
        for path in dependency_contract["dependencyFiles"]
    ]
    for dependency in dependency_files:
        if not dependency.is_file():
            raise BenchmarkError(
                f"BoringSSL build dependency changed or disappeared: "
                f"{dependency}"
            )
    content_manifest = "\n".join(
        f"{dependency}\0{file_sha256(dependency)}"
        for dependency in dependency_files
    )
    content_manifest_sha256 = hashlib.sha256(
        content_manifest.encode("utf-8")
    ).hexdigest()
    if (
        content_manifest_sha256
        != dependency_contract["dependencyContentManifestSHA256"]
    ):
        raise BenchmarkError(
            "BoringSSL build dependency contents changed during benchmark"
        )
    return {
        "dependencyContentManifestSHA256": content_manifest_sha256,
        "dependencyFileCount": len(dependency_files),
        "unchanged": True,
    }


def write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path, follow_symlinks=False)
        temporary_path.unlink()
        temporary_path = None
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    options = parser.parse_args(arguments)
    if options.samples < MINIMUM_SAMPLE_COUNT:
        parser.error(f"--samples must be at least {MINIMUM_SAMPLE_COUNT}")
    if options.samples % 2 != 0:
        parser.error("--samples must be even for balanced AB/BA ordering")
    if options.bootstrap_resamples < MINIMUM_BOOTSTRAP_RESAMPLES:
        parser.error(
            f"--bootstrap-resamples must be at least {MINIMUM_BOOTSTRAP_RESAMPLES}"
        )

    try:
        output_path = (
            options.output or default_output_path()
        ).expanduser().resolve()
        output_exists = output_path.exists()
    except (OSError, RuntimeError) as error:
        print(
            "Benchmark invalid: could not resolve the artifact output path: "
            f"{error}",
            file=sys.stderr,
        )
        return 2
    if output_exists:
        parser.error(f"refusing to overwrite existing output: {output_path}")
    requested_build_root = options.build_root or default_build_root()

    seed = options.seed if options.seed is not None else secrets.randbits(63)
    artifact: dict[str, Any] = {
        "schemaVersion": ARTIFACT_SCHEMA_VERSION,
        "status": "initializing",
        "startedAt": utc_now(),
        "scope": {
            "algorithm": "SHA-256",
            "platform": "Native",
            "comparison": "Pure Swift versus pinned official BoringSSL",
            "headlineByteCounts": list(HEADLINE_BYTE_COUNTS),
            "wasiMeasured": False,
            "embeddedMeasured": False,
        },
        "configuration": {
            "pairedSampleCountPerWorkload": options.samples,
            "bootstrapResamples": options.bootstrap_resamples,
            "rootSeed": seed,
            "workerTimeoutSeconds": options.worker_timeout_seconds,
            "buildTimeoutSeconds": options.build_timeout_seconds,
            "minimumSampleNanoseconds": MINIMUM_SAMPLE_NANOSECONDS,
            "minimumSpeedup": TARGET_SPEEDUP,
            "validationIterationsPerWorkload": VALIDATION_ITERATION_COUNT,
            "convergenceWindow": CONVERGENCE_WINDOW,
            "convergenceTolerance": CONVERGENCE_TOLERANCE,
        },
        "memoryEvidence": {
            "allocationCountMeasured": False,
            "copyCountMeasured": False,
            "note": (
                "This timing runner does not establish allocation or copy budgets; "
                "those require a separate instrumented artifact."
            ),
        },
        "storage": {
            "minimumBuildAvailableBytes": MINIMUM_BUILD_AVAILABLE_BYTES,
            "minimumArtifactReserveBytes": MINIMUM_ARTIFACT_RESERVE_BYTES,
        },
    }

    try:
        storage_paths = {
            "artifactOutput": output_path,
            "buildRoot": requested_build_root,
        }
        artifact["storage"]["atStart"] = collect_storage_capacity(
            storage_paths
        )
        require_available_storage(
            artifact["storage"]["atStart"],
            minimum_available_bytes=MINIMUM_BUILD_AVAILABLE_BYTES,
            phase="benchmark start",
        )
        boringssl_source = options.boringssl_source.expanduser().resolve()
        swift_repository = git_metadata(REPOSITORY_ROOT)
        boringssl_repository = git_metadata(boringssl_source)
        validate_boringssl_repository(boringssl_repository)
        toolchain = collect_toolchain_metadata()
        host_metadata = collect_host_metadata()
        if host_metadata["hardwareModel"] is None:
            raise BenchmarkError("hardware model is unavailable")
        if host_metadata["operatingSystem"] is None:
            raise BenchmarkError("operating system metadata is unavailable")
        if host_metadata["sha256Feature"] != "1":
            raise BenchmarkError(
                "host does not report ARM FEAT_SHA256 capability"
            )
        initial_quiescence = collect_quiescence()
        eligibility_reasons = formal_eligibility_reasons(
            swift_repository,
            toolchain,
            initial_quiescence,
        )
        formal_eligible = not eligibility_reasons
        artifact["formalEvidence"] = {
            "requested": options.formal,
            "eligibleAtStart": formal_eligible,
            "classification": (
                "formal"
                if options.formal and formal_eligible
                else (
                    "invalid-formal-request"
                    if options.formal
                    else "exploratory"
                )
            ),
            "ineligibilityReasons": eligibility_reasons,
        }
        if options.formal and not formal_eligible:
            raise BenchmarkError(
                "formal run preconditions failed: " + "; ".join(eligibility_reasons)
            )

        artifact["provenance"] = {
            "sslAtStart": swift_repository,
            "boringSSLAtStart": boringssl_repository,
            "toolchain": toolchain,
            "host": host_metadata,
            "initialQuiescence": initial_quiescence,
            "runner": {
                "path": str(Path(__file__).resolve()),
                "sha256": file_sha256(Path(__file__).resolve()),
                "arguments": list(sys.argv[1:] if arguments is None else arguments),
            },
        }

        build_root = prepare_build_root(requested_build_root)
        source_snapshots: dict[str, Any] | None = None
        build_swift_source = REPOSITORY_ROOT
        build_boringssl_source = boringssl_source
        if options.formal:
            source_snapshots = create_formal_source_snapshots(
                build_root=build_root,
                swift_repository=swift_repository,
                boringssl_repository=boringssl_repository,
                timeout_seconds=options.build_timeout_seconds,
            )
            artifact["sourceSnapshots"] = source_snapshots
            build_swift_source = Path(
                source_snapshots["ssl"]["sourcePath"]
            )
            build_boringssl_source = Path(
                source_snapshots["boringSSL"]["sourcePath"]
            )
        else:
            artifact["sourceSnapshots"] = {
                "mode": "live working trees for exploratory run",
                "readOnly": False,
            }
        artifact["status"] = "building"
        builds = build_workers(
            build_root=build_root,
            swift_source=build_swift_source,
            boringssl_source=build_boringssl_source,
            boringssl_commit=boringssl_repository["commit"],
            toolchain=toolchain,
            timeout_seconds=options.build_timeout_seconds,
        )
        artifact["builds"] = builds
        artifact["storage"]["atPostBuild"] = collect_storage_capacity(
            storage_paths
        )
        require_available_storage(
            artifact["storage"]["atPostBuild"],
            minimum_available_bytes=MINIMUM_ARTIFACT_RESERVE_BYTES,
            phase="post-build artifact reservation",
        )
        swift_worker = Path(builds["swift"]["worker"]["path"])
        boringssl_worker = Path(builds["boringSSL"]["worker"]["path"])

        artifact["postBuildQuiescence"] = wait_for_quiescence(
            options.quiescence_timeout_seconds
        )

        artifact["status"] = "validating"
        artifact["validation"] = validate_full_outputs(
            swift_worker,
            boringssl_worker,
            timeout_seconds=options.worker_timeout_seconds,
        )

        workload_order = list(HEADLINE_BYTE_COUNTS)
        random.Random(seed ^ 0x574F524B4C4F4144).shuffle(workload_order)
        artifact["workloadOrder"] = workload_order
        workload_results: list[dict[str, Any]] = []
        artifact["status"] = "sampling"
        for workload_index, byte_count in enumerate(workload_order):
            calibration = calibrate_iterations(
                swift_worker,
                boringssl_worker,
                byte_count=byte_count,
                timeout_seconds=options.worker_timeout_seconds,
            )
            convergence = verify_timing_convergence(
                swift_worker,
                boringssl_worker,
                byte_count=byte_count,
                iterations=calibration["iterationsPerSample"],
                warmup_iterations=calibration["warmupIterationsPerInvocation"],
                timeout_seconds=options.worker_timeout_seconds,
            )
            workload_seed = seed ^ (byte_count << 17) ^ workload_index
            result = sample_workload(
                swift_worker,
                boringssl_worker,
                byte_count=byte_count,
                iterations=calibration["iterationsPerSample"],
                warmup_iterations=calibration["warmupIterationsPerInvocation"],
                sample_count=options.samples,
                bootstrap_resamples=options.bootstrap_resamples,
                seed=workload_seed,
                timeout_seconds=options.worker_timeout_seconds,
            )
            result["calibration"] = calibration
            result["convergence"] = convergence
            workload_results.append(result)

        workload_results.sort(key=lambda workload: workload["byteCount"])
        artifact["workloads"] = workload_results
        decision = overall_decision(workload_results)
        artifact["target"] = {
            "minimumSpeedup": TARGET_SPEEDUP,
            "criterion": (
                "every fixed headline workload must have a paired median "
                "speedup 95% bootstrap confidence-interval lower bound of 1.10"
            ),
            "decision": decision,
        }

        swift_repository_at_end = git_metadata(REPOSITORY_ROOT)
        boringssl_repository_at_end = git_metadata(boringssl_source)
        swift_worker_at_end = executable_metadata(swift_worker)
        boringssl_worker_at_end = executable_metadata(boringssl_worker)
        verify_repository_unchanged(
            label="swift-ssl",
            initial=swift_repository,
            final=swift_repository_at_end,
            formal=options.formal,
        )
        verify_repository_unchanged(
            label="BoringSSL",
            initial=boringssl_repository,
            final=boringssl_repository_at_end,
            formal=True,
        )
        verify_executable_unchanged(
            label="Pure Swift",
            initial=builds["swift"]["worker"],
            final=swift_worker_at_end,
        )
        verify_executable_unchanged(
            label="BoringSSL",
            initial=builds["boringSSL"]["worker"],
            final=boringssl_worker_at_end,
        )
        artifact["builds"]["boringSSL"]["dependencyContractAtEnd"] = (
            verify_dependency_content_manifest_unchanged(
                builds["boringSSL"]["dependencyContract"]
            )
        )
        if source_snapshots is not None:
            artifact["sourceSnapshotsAtEnd"] = (
                verify_formal_source_snapshots_unchanged(source_snapshots)
            )
        artifact["provenance"]["trustedExecutablesAtEnd"] = (
            verify_executable_metadata_unchanged(
                toolchain["trustedExecutables"]
            )
        )
        final_quiescence = collect_quiescence()
        final_quiescence_reasons = quiescence_reasons(final_quiescence)
        if final_quiescence_reasons:
            raise BenchmarkError(
                "host failed final quiescence validation: "
                + "; ".join(final_quiescence_reasons)
            )
        artifact["provenance"]["sslAtEnd"] = swift_repository_at_end
        artifact["provenance"]["boringSSLAtEnd"] = boringssl_repository_at_end
        artifact["provenance"]["swiftWorkerAtEnd"] = swift_worker_at_end
        artifact["provenance"]["boringSSLWorkerAtEnd"] = boringssl_worker_at_end
        artifact["provenance"]["finalQuiescence"] = final_quiescence

        artifact["storage"]["atEnd"] = collect_storage_capacity(storage_paths)
        require_available_storage(
            artifact["storage"]["atEnd"],
            minimum_available_bytes=MINIMUM_ARTIFACT_RESERVE_BYTES,
            phase="final artifact write",
        )
        artifact["releaseGateSatisfied"] = False
        artifact["releaseGateLimitations"] = [
            "allocation and copy budgets were not measured by this runner",
            "WASI and Embedded performance were not measured",
        ]
        artifact["status"] = "complete"
        artifact["finishedAt"] = utc_now()
        write_json_atomically(output_path, artifact)

        classification = artifact["formalEvidence"]["classification"]
        print(f"Decision: {decision} ({classification} timing evidence)")
        for workload in workload_results:
            speedup = workload["statistics"]["pairedSpeedup"]
            interval = speedup["confidenceInterval95"]
            print(
                f"{workload['byteCount']} bytes: "
                f"median {speedup['median']:.6f}, "
                f"95% CI [{interval['lower']:.6f}, "
                f"{interval['upper']:.6f}], "
                f"{workload['target']['decision']}"
            )
        print(f"Raw artifact: {output_path}")
        return 0 if decision == "pass" else 1
    except Exception as error:
        artifact["status"] = "invalid"
        artifact["error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "expectedContractFailure": isinstance(error, BenchmarkError),
        }
        try:
            artifact["storage"]["atFailure"] = collect_storage_capacity(
                {
                    "artifactOutput": output_path,
                    "buildRoot": requested_build_root,
                }
            )
        except Exception as storage_error:
            artifact["storage"]["failureObservationError"] = {
                "type": type(storage_error).__name__,
                "message": str(storage_error),
            }
        artifact["finishedAt"] = utc_now()
        print(f"Benchmark invalid: {error}", file=sys.stderr)
        try:
            write_json_atomically(output_path, artifact)
        except Exception as artifact_error:
            print(
                "Failure artifact unavailable: "
                f"{type(artifact_error).__name__}: {artifact_error}",
                file=sys.stderr,
            )
        else:
            print(f"Failure artifact: {output_path}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
