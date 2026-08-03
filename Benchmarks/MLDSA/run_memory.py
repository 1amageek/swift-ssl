#!/usr/bin/env python3
"""Build and measure ML-DSA allocation and bulk-copy budgets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLCHAIN_ID = "org.swift.64202607231a"
SWIFT_COMMIT = "ef761e567dc94ee"
DEVELOPER_DIR = pathlib.Path("/Applications/Xcode-beta.app/Contents/Developer")
TARGET = "arm64-apple-macosx15.0"
MINIMUM_OS = "15.0"
EXPECTED_SDK_VERSION = "27.0"
ITERATION_COUNTS = (1, 10, 100)
REPETITIONS = 3
PARAMETER_SETS = (44, 65, 87)
COUNTER_NAMES = (
    "mallocCalls",
    "mallocBytes",
    "callocCalls",
    "callocBytes",
    "reallocCalls",
    "reallocBytes",
    "alignedCalls",
    "alignedBytes",
    "freeCalls",
    "memcpyCalls",
    "memcpyBytes",
    "memmoveCalls",
    "memmoveBytes",
)
EXPECTED_BUDGETS = {
    "mldsa44-keygen": {
        "allocationCalls": 23,
        "allocationBytes": 44_928,
        "bulkCopyCalls": 6,
        "bulkCopyBytes": 0,
    },
    "mldsa44-sign": {
        "allocationCalls": 30,
        "allocationBytes": 38_800,
        "bulkCopyCalls": 4,
        "bulkCopyBytes": 16_384,
    },
    "mldsa44-verify": {
        "allocationCalls": 14,
        "allocationBytes": 23_488,
        "bulkCopyCalls": 1,
        "bulkCopyBytes": 0,
    },
    "mldsa65-keygen": {
        "allocationCalls": 25,
        "allocationBytes": 71_536,
        "bulkCopyCalls": 6,
        "bulkCopyBytes": 0,
    },
    "mldsa65-sign": {
        "allocationCalls": 62,
        "allocationBytes": 59_248,
        "bulkCopyCalls": 8,
        "bulkCopyBytes": 40_960,
    },
    "mldsa65-verify": {
        "allocationCalls": 14,
        "allocationBytes": 31_712,
        "bulkCopyCalls": 1,
        "bulkCopyBytes": 0,
    },
    "mldsa87-keygen": {
        "allocationCalls": 25,
        "allocationBytes": 111_088,
        "bulkCopyCalls": 6,
        "bulkCopyBytes": 0,
    },
    "mldsa87-sign": {
        "allocationCalls": 48,
        "allocationBytes": 71_120,
        "bulkCopyCalls": 6,
        "bulkCopyBytes": 43_008,
    },
    "mldsa87-verify": {
        "allocationCalls": 14,
        "allocationBytes": 42_240,
        "bulkCopyCalls": 1,
        "bulkCopyBytes": 0,
    },
}


class MeasurementError(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as error:
        raise MeasurementError(
            f"command failed ({error.returncode}): {' '.join(command)}\n"
            f"stdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise MeasurementError(f"command timed out: {' '.join(command)}") from error


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def executable_identity(path: pathlib.Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(path),
        "resolvedPath": str(resolved),
        "sizeBytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def mach_o_contract(
    path: pathlib.Path,
    *,
    lipo: pathlib.Path,
    vtool: pathlib.Path,
) -> dict[str, Any]:
    architectures = run([str(lipo), "-archs", str(path)]).stdout.strip().split()
    build_version = run([str(vtool), "-show-build", str(path)]).stdout
    passed = (
        architectures == ["arm64"]
        and "platform MACOS" in build_version
        and f"minos {MINIMUM_OS}" in build_version
        and f"sdk {EXPECTED_SDK_VERSION}" in build_version
    )
    if not passed:
        raise MeasurementError(f"Mach-O contract failed for {path}:\n{build_version}")
    return {
        "architectures": architectures,
        "platform": "MACOS",
        "minimumOS": MINIMUM_OS,
        "sdk": EXPECTED_SDK_VERSION,
        "vtoolOutput": build_version,
        "passed": True,
    }


def parse_allocation_output(output: str) -> tuple[dict[str, int], dict[str, int]]:
    allocation_line = next(
        (line for line in output.splitlines() if line.startswith("ALLOCATION_RESULT,")),
        None,
    )
    checksum_line = next(
        (line for line in output.splitlines() if line.startswith("MEMORY_CHECKSUM,")),
        None,
    )
    if allocation_line is None or checksum_line is None:
        raise MeasurementError(f"incomplete allocation output:\n{output}")
    allocation_values = allocation_line.split(",")[1:]
    checksum_values = checksum_line.split(",")[1:]
    if len(allocation_values) != len(COUNTER_NAMES) or len(checksum_values) != 2:
        raise MeasurementError(f"invalid allocation output:\n{output}")
    counters = {
        name: int(value, 10) for name, value in zip(COUNTER_NAMES, allocation_values)
    }
    checksum = {
        "iterations": int(checksum_values[0], 10),
        "value": int(checksum_values[1], 10),
    }
    return counters, checksum


def derive_linear_counters(observations: list[dict[str, Any]]) -> dict[str, Any]:
    by_iterations: dict[int, list[dict[str, int]]] = {}
    checksums: dict[int, set[int]] = {}
    for observation in observations:
        iterations = observation["iterations"]
        by_iterations.setdefault(iterations, []).append(observation["counters"])
        checksums.setdefault(iterations, set()).add(observation["checksum"])
    if tuple(sorted(by_iterations)) != ITERATION_COUNTS:
        raise MeasurementError("iteration-count contract is incomplete")
    canonical: dict[int, dict[str, int]] = {}
    for iterations, counters in by_iterations.items():
        if len(counters) != REPETITIONS or any(item != counters[0] for item in counters[1:]):
            raise MeasurementError(f"counters are not deterministic at {iterations} iterations")
        if len(checksums[iterations]) != 1:
            raise MeasurementError(f"checksum is not deterministic at {iterations} iterations")
        canonical[iterations] = counters[0]

    per_operation: dict[str, int] = {}
    fixed_overhead: dict[str, int] = {}
    low = ITERATION_COUNTS[-2]
    high = ITERATION_COUNTS[-1]
    denominator = high - low
    for name in COUNTER_NAMES:
        numerator = canonical[high][name] - canonical[low][name]
        quotient, remainder = divmod(numerator, denominator)
        if remainder != 0 or quotient < 0:
            raise MeasurementError(f"{name} does not have a nonnegative integral slope")
        intercept = canonical[high][name] - quotient * high
        for iterations in ITERATION_COUNTS:
            if canonical[iterations][name] != intercept + quotient * iterations:
                raise MeasurementError(f"{name} is not linear across iteration counts")
        per_operation[name] = quotient
        fixed_overhead[name] = intercept

    allocation_calls = sum(
        per_operation[name]
        for name in ("mallocCalls", "callocCalls", "reallocCalls", "alignedCalls")
    )
    allocation_bytes = sum(
        per_operation[name]
        for name in ("mallocBytes", "callocBytes", "reallocBytes", "alignedBytes")
    )
    copy_calls = per_operation["memcpyCalls"] + per_operation["memmoveCalls"]
    copy_bytes = per_operation["memcpyBytes"] + per_operation["memmoveBytes"]
    return {
        "perOperation": {
            **per_operation,
            "allocationCalls": allocation_calls,
            "allocationBytes": allocation_bytes,
            "bulkCopyCalls": copy_calls,
            "bulkCopyBytes": copy_bytes,
        },
        "fixedProcessOverhead": fixed_overhead,
        "canonicalObservations": {
            str(iterations): canonical[iterations] for iterations in ITERATION_COUNTS
        },
    }


def validate_budget(workload: str, derived: dict[str, Any]) -> list[str]:
    values = derived["perOperation"]
    expected = EXPECTED_BUDGETS[workload]
    failures: list[str] = []
    for name in (
        "allocationCalls",
        "allocationBytes",
        "bulkCopyCalls",
        "bulkCopyBytes",
    ):
        if values[name] != expected[name]:
            failures.append(f"{name} expected {expected[name]}, observed {values[name]}")
    if values["callocCalls"] != 0 or values["reallocCalls"] != 0:
        failures.append("calloc/realloc must not occur per operation")
    if values["freeCalls"] != values["allocationCalls"]:
        failures.append(
            f"allocation/free imbalance: {values['allocationCalls']} allocations, "
            f"{values['freeCalls']} frees"
        )
    return failures


def create_snapshot(source: pathlib.Path, destination: pathlib.Path) -> dict[str, Any]:
    commit = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
    status = run(["git", "status", "--porcelain"], cwd=source).stdout
    if status:
        raise MeasurementError("formal memory measurement requires a clean source checkout")
    archive = destination.with_suffix(".tar")
    with archive.open("wb") as stream:
        process = subprocess.run(
            ["git", "archive", "--format=tar", commit],
            cwd=source,
            check=True,
            stdout=stream,
            stderr=subprocess.PIPE,
        )
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r") as stream:
        stream.extractall(destination, filter="data")
    return {
        "commit": commit,
        "archiveSHA256": sha256_file(archive),
        "treeSHA256": tree_sha256(destination),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--formal", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()
    if not arguments.formal:
        raise MeasurementError("only --formal measurements may create this artifact")
    if os.environ.get("TOOLCHAINS") != TOOLCHAIN_ID:
        raise MeasurementError(f"TOOLCHAINS must equal {TOOLCHAIN_ID}")
    if not DEVELOPER_DIR.is_dir():
        raise MeasurementError(f"missing developer directory: {DEVELOPER_DIR}")

    xcrun = pathlib.Path("/usr/bin/xcrun")
    discovery_env = dict(os.environ)
    discovery_env["DEVELOPER_DIR"] = str(DEVELOPER_DIR)
    swift = pathlib.Path(
        run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "swift"],
            env=discovery_env,
        ).stdout.strip()
    )
    clang = pathlib.Path(
        run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "clang"],
            env=discovery_env,
        ).stdout.strip()
    )
    lipo = pathlib.Path(run([str(xcrun), "--find", "lipo"], env=discovery_env).stdout.strip())
    vtool = pathlib.Path(run([str(xcrun), "--find", "vtool"], env=discovery_env).stdout.strip())
    swift_version = run([str(swift), "--version"]).stdout
    if SWIFT_COMMIT not in swift_version:
        raise MeasurementError("unexpected Swift compiler commit")
    tool_env = {
        "DEVELOPER_DIR": str(DEVELOPER_DIR),
        "HOME": os.environ["HOME"],
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": os.environ.get("LOGNAME", ""),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "SWIFT_SSL_ENABLE_BENCHMARKS": "1",
        "TOOLCHAINS": TOOLCHAIN_ID,
        "USER": os.environ.get("USER", ""),
    }
    sdk = pathlib.Path(
        run([str(xcrun), "--sdk", "macosx", "--show-sdk-path"], env=tool_env).stdout.strip()
    )
    sdk_version = run(
        [str(xcrun), "--sdk", "macosx", "--show-sdk-version"], env=tool_env
    ).stdout.strip()
    if sdk_version != EXPECTED_SDK_VERSION:
        raise MeasurementError(f"expected SDK {EXPECTED_SDK_VERSION}, observed {sdk_version}")
    tool_env["SDKROOT"] = str(sdk)

    build_parent = ROOT / ".build" / "benchmark-mldsa-memory"
    build_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=build_parent) as temporary:
        run_root = pathlib.Path(temporary)
        snapshot = run_root / "swift-ssl"
        snapshot_evidence = create_snapshot(ROOT, snapshot)
        scratch = run_root / "swift-build"
        build_command = [
            str(swift),
            "build",
            "--build-system",
            "native",
            "--disable-dependency-cache",
            "--disable-build-manifest-caching",
            "--scratch-path",
            str(scratch),
            "--configuration",
            "release",
            "--triple",
            TARGET,
            "--sdk",
            str(sdk),
            "--jobs",
            "2",
            "--product",
            "swift-ssl-mldsa-benchmark",
        ]
        build_result = run(build_command, cwd=snapshot, env=tool_env, timeout=900)
        worker = scratch / "arm64-apple-macosx" / "release" / "swift-ssl-mldsa-benchmark"
        if not worker.is_file():
            raise MeasurementError(f"missing benchmark worker: {worker}")

        probe = run_root / "libSSLMLDSAAllocationProbe.dylib"
        contract = run_root / "allocation-probe-contract"
        probe_source = snapshot / "Benchmarks/MLDSA/AllocationProbe/MLDSAAllocationProbe.c"
        contract_source = snapshot / "Benchmarks/MLDSA/AllocationProbe/AllocationProbeContract.c"
        common_compile = [
            str(clang),
            "-O2",
            "-std=c11",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-arch",
            "arm64",
            f"-mmacosx-version-min={MINIMUM_OS}",
            "-isysroot",
            str(sdk),
        ]
        run(common_compile + ["-dynamiclib", str(probe_source), "-o", str(probe)])
        run(common_compile + [str(contract_source), "-o", str(contract)])
        binary_identities = {
            "worker": {
                **executable_identity(worker),
                "machO": mach_o_contract(worker, lipo=lipo, vtool=vtool),
            },
            "allocationProbe": {
                **executable_identity(probe),
                "machO": mach_o_contract(probe, lipo=lipo, vtool=vtool),
            },
            "contractProbe": {
                **executable_identity(contract),
                "machO": mach_o_contract(contract, lipo=lipo, vtool=vtool),
            },
        }

        injected_env = dict(tool_env)
        injected_env["DYLD_INSERT_LIBRARIES"] = str(probe)
        contract_result = run([str(contract)], env=injected_env)
        contract_counters, _ = parse_allocation_output(
            contract_result.stdout.replace("PROBE_CHECKSUM", "MEMORY_CHECKSUM,1")
        )
        expected_contract = {
            "mallocCalls": 1,
            "mallocBytes": 17,
            "callocCalls": 1,
            "callocBytes": 38,
            "reallocCalls": 1,
            "reallocBytes": 41,
            "alignedCalls": 1,
            "alignedBytes": 128,
            "freeCalls": 4,
            "memcpyCalls": 0,
            "memcpyBytes": 0,
            "memmoveCalls": 2,
            "memmoveBytes": 20,
        }
        if contract_counters != expected_contract:
            raise MeasurementError(
                f"allocation probe self-test failed: {contract_counters!r}"
            )

        results: dict[str, Any] = {}
        all_passed = True
        for parameter_set in PARAMETER_SETS:
            for operation in ("keygen", "sign", "verify"):
                workload = f"mldsa{parameter_set}-{operation}"
                observations: list[dict[str, Any]] = []
                for iterations in ITERATION_COUNTS:
                    for repetition in range(REPETITIONS):
                        measured = run(
                            [
                                str(worker),
                                "--memory",
                                str(parameter_set),
                                operation,
                                str(iterations),
                            ],
                            env=injected_env,
                        )
                        counters, checksum = parse_allocation_output(measured.stdout)
                        if checksum["iterations"] != iterations:
                            raise MeasurementError(
                                "worker reported the wrong iteration count"
                            )
                        observations.append(
                            {
                                "iterations": iterations,
                                "repetition": repetition,
                                "counters": counters,
                                "checksum": checksum["value"],
                            }
                        )
                derived = derive_linear_counters(observations)
                failures = validate_budget(workload, derived)
                passed = not failures
                all_passed = all_passed and passed
                results[workload] = {
                    "parameterSet": parameter_set,
                    "operation": operation,
                    "passed": passed,
                    "failures": failures,
                    "budget": EXPECTED_BUDGETS[workload],
                    "derived": derived,
                    "observations": observations,
                }

        completed = dt.datetime.now(dt.timezone.utc)
        final_source_commit = run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
        final_source_status = run(["git", "status", "--porcelain"], cwd=ROOT).stdout
        final_snapshot_tree = tree_sha256(snapshot)
        final_binary_identities = {
            "worker": executable_identity(worker),
            "allocationProbe": executable_identity(probe),
            "contractProbe": executable_identity(contract),
        }
        if final_source_commit != snapshot_evidence["commit"] or final_source_status:
            raise MeasurementError("source checkout changed during formal measurement")
        if final_snapshot_tree != snapshot_evidence["treeSHA256"]:
            raise MeasurementError("read-only source snapshot changed during measurement")
        for name, identity in final_binary_identities.items():
            if identity["sha256"] != binary_identities[name]["sha256"]:
                raise MeasurementError(f"{name} changed during measurement")
        artifact = {
            "schemaVersion": 1,
            "classification": "formal",
            "valid": True,
            "passed": all_passed,
            "completedAt": completed.isoformat(),
            "measurement": "allocation and dynamic bulk-copy interposition",
            "scope": (
                "public entropy-injected key generation, public in-place signing, "
                "and public verification loops; reusable setup excluded"
            ),
            "limitations": [
                "Dynamic memcpy/memmove interposition does not observe compiler-inlined scalar copies.",
                "Requested allocation bytes are recorded; allocator size classes are not.",
                "The artifact is Native-only and is not timing evidence.",
            ],
            "source": snapshot_evidence,
            "toolchain": {
                "identifier": TOOLCHAIN_ID,
                "swiftCompilerCommit": SWIFT_COMMIT,
                "swiftVersion": swift_version.strip(),
                "sdkPath": str(sdk),
                "sdkVersion": sdk_version,
                "target": TARGET,
                "minimumOS": MINIMUM_OS,
            },
            "build": {
                "command": build_command,
                "stdoutSHA256": hashlib.sha256(
                    build_result.stdout.encode("utf-8")
                ).hexdigest(),
                "stderrSHA256": hashlib.sha256(
                    build_result.stderr.encode("utf-8")
                ).hexdigest(),
            },
            "tools": {
                "swift": executable_identity(swift),
                "clang": executable_identity(clang),
                "lipo": executable_identity(lipo),
                "vtool": executable_identity(vtool),
            },
            "binaries": binary_identities,
            "finalEvidence": {
                "sourceCommit": final_source_commit,
                "sourceClean": True,
                "snapshotTreeSHA256": final_snapshot_tree,
                "binaries": final_binary_identities,
            },
            "probeContract": {
                "passed": True,
                "expected": expected_contract,
                "observed": contract_counters,
                "stdoutSHA256": hashlib.sha256(
                    contract_result.stdout.encode("utf-8")
                ).hexdigest(),
            },
            "iterationCounts": list(ITERATION_COUNTS),
            "repetitions": REPETITIONS,
            "results": results,
        }
        output = arguments.output
        if output is None:
            timestamp = completed.strftime("%Y%m%dT%H%M%SZ")
            output = ROOT / "Benchmarks/MLDSA/Results" / f"{timestamp}-native-mldsa-memory.json"
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise MeasurementError(f"refusing to overwrite existing artifact: {output}")
        temporary_output = output.with_suffix(output.suffix + ".tmp")
        temporary_output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
        os.replace(temporary_output, output)
        print(json.dumps({"artifact": str(output), "passed": all_passed}, sort_keys=True))
        return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MeasurementError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
