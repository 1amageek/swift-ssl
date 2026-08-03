#!/usr/bin/env python3
"""Build and measure HPKE allocation and dynamic bulk-copy budgets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
SUPPORT_PATH = ROOT / "Benchmarks/MLKEM/run_memory.py"
SUPPORT_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_mlkem_memory_support", SUPPORT_PATH
)
if SUPPORT_SPEC is None or SUPPORT_SPEC.loader is None:
    raise RuntimeError(f"cannot load trusted memory support: {SUPPORT_PATH}")
support = importlib.util.module_from_spec(SUPPORT_SPEC)
SUPPORT_SPEC.loader.exec_module(support)

TOOLCHAIN_ID = support.TOOLCHAIN_ID
SWIFT_COMMIT = support.SWIFT_COMMIT
DEVELOPER_DIR = support.DEVELOPER_DIR
TARGET = support.TARGET
MINIMUM_OS = support.MINIMUM_OS
EXPECTED_SDK_VERSION = support.EXPECTED_SDK_VERSION
ITERATION_COUNTS = support.ITERATION_COUNTS
REPETITIONS = support.REPETITIONS
MeasurementError = support.MeasurementError
WORKLOADS = (
    {
        "name": "x25519-shared",
        "operation": "x25519-shared",
        "payloadBytes": 32,
        "authenticatedDataBytes": 0,
    },
    {
        "name": "recipient-setup",
        "operation": "recipient-setup",
        "payloadBytes": 256,
        "authenticatedDataBytes": 32,
    },
    {
        "name": "first-open-256",
        "operation": "first-open",
        "payloadBytes": 256,
        "authenticatedDataBytes": 32,
    },
    {
        "name": "first-open-1536",
        "operation": "first-open",
        "payloadBytes": 1_536,
        "authenticatedDataBytes": 377,
    },
    {
        "name": "p256-shared",
        "operation": "p256-shared",
        "payloadBytes": 32,
        "authenticatedDataBytes": 0,
    },
    {
        "name": "p256-sender-setup",
        "operation": "p256-sender-setup",
        "payloadBytes": 1,
        "authenticatedDataBytes": 0,
    },
    {
        "name": "p256-recipient-setup",
        "operation": "p256-recipient-setup",
        "payloadBytes": 1,
        "authenticatedDataBytes": 0,
    },
)
EXPECTED_BUDGETS = {
    "x25519-shared": {
        "allocationCalls": 0,
        "allocationBytes": 0,
        "bulkCopyBytes": 0,
        "mallocCalls": 0,
        "alignedCalls": 0,
    },
    "recipient-setup": {
        "allocationCalls": 2,
        "allocationBytes": 412,
        "bulkCopyBytes": 1_715,
        "mallocCalls": 1,
        "alignedCalls": 1,
    },
    "first-open-256": {
        "allocationCalls": 2,
        "allocationBytes": 412,
        "bulkCopyBytes": 2_331,
        "mallocCalls": 1,
        "alignedCalls": 1,
    },
    "first-open-1536": {
        "allocationCalls": 2,
        "allocationBytes": 412,
        "bulkCopyBytes": 2_331,
        "mallocCalls": 1,
        "alignedCalls": 1,
    },
    "p256-shared": {
        "allocationCalls": 0,
        "allocationBytes": 0,
        "bulkCopyBytes": 0,
        "mallocCalls": 0,
        "alignedCalls": 0,
    },
    "p256-sender-setup": {
        "allocationCalls": 5,
        "allocationBytes": 605,
        "bulkCopyBytes": 1_788,
        "mallocCalls": 3,
        "alignedCalls": 2,
    },
    "p256-recipient-setup": {
        "allocationCalls": 2,
        "allocationBytes": 412,
        "bulkCopyBytes": 1_788,
        "mallocCalls": 1,
        "alignedCalls": 1,
    },
}


def validate_budget(workload: str, derived: dict[str, Any]) -> list[str]:
    values = derived["perOperation"]
    expected = EXPECTED_BUDGETS[workload]
    failures: list[str] = []
    for name in (
        "allocationCalls",
        "allocationBytes",
        "bulkCopyBytes",
        "mallocCalls",
        "alignedCalls",
    ):
        if values[name] != expected[name]:
            failures.append(f"{name} expected {expected[name]}, observed {values[name]}")
    if values["callocCalls"] != 0 or values["reallocCalls"] != 0:
        failures.append("calloc/realloc must not occur per operation")
    if values["memcpyBytes"] != 0:
        failures.append(
            f"memcpyBytes expected 0, observed {values['memcpyBytes']}"
        )
    if values["freeCalls"] != values["allocationCalls"]:
        failures.append(
            f"allocation/free imbalance: {values['allocationCalls']} allocations, "
            f"{values['freeCalls']} frees"
        )
    return failures


def validate_cross_workload_budgets(results: dict[str, Any]) -> list[str]:
    small = results["first-open-256"]["derived"]["perOperation"]
    large = results["first-open-1536"]["derived"]["perOperation"]
    failures: list[str] = []
    for name in ("allocationCalls", "allocationBytes", "bulkCopyBytes"):
        if small[name] != large[name]:
            failures.append(
                f"first-open {name} scales with payload: "
                f"256-byte={small[name]}, 1536-byte={large[name]}"
            )
    return failures


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
        support.run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "swift"],
            env=discovery_env,
        ).stdout.strip()
    )
    clang = pathlib.Path(
        support.run(
            [str(xcrun), "--toolchain", TOOLCHAIN_ID, "--find", "clang"],
            env=discovery_env,
        ).stdout.strip()
    )
    lipo = pathlib.Path(
        support.run([str(xcrun), "--find", "lipo"], env=discovery_env).stdout.strip()
    )
    vtool = pathlib.Path(
        support.run([str(xcrun), "--find", "vtool"], env=discovery_env).stdout.strip()
    )
    swift_version = support.run([str(swift), "--version"]).stdout
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
        support.run(
            [str(xcrun), "--sdk", "macosx", "--show-sdk-path"], env=tool_env
        ).stdout.strip()
    )
    sdk_version = support.run(
        [str(xcrun), "--sdk", "macosx", "--show-sdk-version"], env=tool_env
    ).stdout.strip()
    if sdk_version != EXPECTED_SDK_VERSION:
        raise MeasurementError(
            f"expected SDK {EXPECTED_SDK_VERSION}, observed {sdk_version}"
        )
    tool_env["SDKROOT"] = str(sdk)

    build_parent = ROOT / ".build/benchmark-hpke-memory"
    build_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=build_parent) as temporary:
        run_root = pathlib.Path(temporary)
        snapshot = run_root / "swift-ssl"
        snapshot_evidence = support.create_snapshot(ROOT, snapshot)
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
            "swift-ssl-hpke-benchmark",
        ]
        build_result = support.run(
            build_command, cwd=snapshot, env=tool_env, timeout=900
        )
        worker = (
            scratch / "arm64-apple-macosx/release/swift-ssl-hpke-benchmark"
        )
        if not worker.is_file():
            raise MeasurementError(f"missing benchmark worker: {worker}")

        probe = run_root / "libSSLHPKEAllocationProbe.dylib"
        contract = run_root / "allocation-probe-contract"
        probe_source = snapshot / "Benchmarks/MLKEM/AllocationProbe/MLKEMAllocationProbe.c"
        contract_source = (
            snapshot / "Benchmarks/MLKEM/AllocationProbe/AllocationProbeContract.c"
        )
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
        support.run(
            common_compile + ["-dynamiclib", str(probe_source), "-o", str(probe)]
        )
        support.run(common_compile + [str(contract_source), "-o", str(contract)])
        binary_identities = {
            "worker": {
                **support.executable_identity(worker),
                "machO": support.mach_o_contract(worker, lipo=lipo, vtool=vtool),
            },
            "allocationProbe": {
                **support.executable_identity(probe),
                "machO": support.mach_o_contract(probe, lipo=lipo, vtool=vtool),
            },
            "contractProbe": {
                **support.executable_identity(contract),
                "machO": support.mach_o_contract(contract, lipo=lipo, vtool=vtool),
            },
        }

        injected_env = dict(tool_env)
        injected_env["DYLD_INSERT_LIBRARIES"] = str(probe)
        contract_result = support.run([str(contract)], env=injected_env)
        contract_counters, _ = support.parse_allocation_output(
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
        for workload in WORKLOADS:
            observations: list[dict[str, Any]] = []
            for iterations in ITERATION_COUNTS:
                for repetition in range(REPETITIONS):
                    measured = support.run(
                        [
                            str(worker),
                            "--memory",
                            workload["operation"],
                            str(workload["payloadBytes"]),
                            str(workload["authenticatedDataBytes"]),
                            str(iterations),
                        ],
                        env=injected_env,
                    )
                    counters, checksum = support.parse_allocation_output(
                        measured.stdout
                    )
                    if checksum["iterations"] != iterations:
                        raise MeasurementError("worker reported the wrong iteration count")
                    observations.append(
                        {
                            "iterations": iterations,
                            "repetition": repetition,
                            "counters": counters,
                            "checksum": checksum["value"],
                        }
                    )
            try:
                derived = support.derive_linear_counters(observations)
            except MeasurementError as error:
                counter_evidence = [
                    {
                        "iterations": observation["iterations"],
                        "repetition": observation["repetition"],
                        "counters": observation["counters"],
                    }
                    for observation in observations
                ]
                raise MeasurementError(
                    f"{workload['name']}: {error}; observations={counter_evidence!r}"
                ) from error
            failures = validate_budget(workload["name"], derived)
            passed = not failures
            all_passed = all_passed and passed
            results[workload["name"]] = {
                "operation": workload["operation"],
                "payloadBytes": workload["payloadBytes"],
                "authenticatedDataBytes": workload["authenticatedDataBytes"],
                "passed": passed,
                "failures": failures,
                "budget": EXPECTED_BUDGETS[workload["name"]],
                "derived": derived,
                "observations": observations,
            }

        cross_workload_failures = validate_cross_workload_budgets(results)
        cross_workload_passed = not cross_workload_failures
        all_passed = all_passed and cross_workload_passed

        completed = dt.datetime.now(dt.timezone.utc)
        final_source_commit = support.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT
        ).stdout.strip()
        final_source_status = support.run(
            ["git", "status", "--porcelain"], cwd=ROOT
        ).stdout
        final_snapshot_tree = support.tree_sha256(snapshot)
        final_binary_identities = {
            "worker": support.executable_identity(worker),
            "allocationProbe": support.executable_identity(probe),
            "contractProbe": support.executable_identity(contract),
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
                "RFC 9180 X25519 recipient setup and first authenticated open, "
                "plus P-256 raw ECDH and sender/recipient setup, using "
                "caller-owned input and output buffers"
            ),
            "unmeasuredWarmupOperations": 1,
            "limitations": [
                "One exact-path warmup operation initializes Swift runtime metadata before each steady-state measurement window; cold-start allocation is outside this artifact.",
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
                "swift": support.executable_identity(swift),
                "clang": support.executable_identity(clang),
                "lipo": support.executable_identity(lipo),
                "vtool": support.executable_identity(vtool),
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
            "crossWorkloadChecks": {
                "firstOpenPayloadIndependentAllocationAndDynamicBulkCopy": {
                    "passed": cross_workload_passed,
                    "failures": cross_workload_failures,
                }
            },
            "results": results,
        }
        output = arguments.output
        if output is None:
            timestamp = completed.strftime("%Y%m%dT%H%M%SZ")
            output = (
                ROOT
                / "Benchmarks/HPKE/Results"
                / f"{timestamp}-native-hpke-memory.json"
            )
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise MeasurementError(f"refusing to overwrite existing artifact: {output}")
        temporary_output = output.with_suffix(output.suffix + ".tmp")
        temporary_output.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n"
        )
        os.replace(temporary_output, output)
        print(
            json.dumps(
                {"artifact": str(output), "passed": all_passed}, sort_keys=True
            )
        )
        return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MeasurementError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(2)
