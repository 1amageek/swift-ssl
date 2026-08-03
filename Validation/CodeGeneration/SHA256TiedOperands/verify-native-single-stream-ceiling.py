#!/usr/bin/env python3

import json
from decimal import Decimal
from pathlib import Path


EXPECTED_OMISSIONS = {
    "input loads",
    "message schedule",
    "round-constant addition",
    "feed-forward",
    "digest output",
    "public API work",
}
EXPECTED_INSTRUCTIONS = {
    "statePreservingMove": 16,
    "sha256h": 16,
    "sha256h2": 16,
}
RATIO_TOLERANCE = Decimal("0.000001")


def decimal(value: object, field: str) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be encoded as a decimal string")
    return Decimal(value)


def main() -> None:
    evidence_path = Path(__file__).with_name("native-single-stream-ceiling.json")
    with evidence_path.open("r", encoding="utf-8") as evidence_file:
        evidence = json.load(evidence_file)

    if evidence.get("schemaVersion") != 1:
        raise ValueError("unsupported ceiling evidence schema")
    if evidence.get("classification") != "diagnostic-impossibility-evidence":
        raise ValueError("the evidence must not be classified as a benchmark pass")

    required_ratio = decimal(
        evidence["comparison"]["requiredRatio"],
        "comparison.requiredRatio",
    )
    if required_ratio <= Decimal(1):
        raise ValueError("the required ratio must exceed one")

    state_only = evidence["stateOnlyKernel"]
    if state_only["instructionsPerBlock"] != EXPECTED_INSTRUCTIONS:
        raise ValueError("the state-only instruction contract changed")
    if set(state_only["omittedRequiredOperations"]) != EXPECTED_OMISSIONS:
        raise ValueError("the state-only omitted-work contract changed")

    mca = state_only["llvmMCA"]
    mca_ratio = decimal(
        mca["boringSSLCyclesPerBlock"],
        "stateOnlyKernel.llvmMCA.boringSSLCyclesPerBlock",
    ) / decimal(
        mca["stateOnlyCyclesPerBlock"],
        "stateOnlyKernel.llvmMCA.stateOnlyCyclesPerBlock",
    )
    recorded_mca_ratio = decimal(
        mca["maximumRatio"],
        "stateOnlyKernel.llvmMCA.maximumRatio",
    )
    if abs(mca_ratio - recorded_mca_ratio) > RATIO_TOLERANCE:
        raise ValueError("the recorded llvm-mca ratio is inconsistent")
    if mca_ratio >= required_ratio:
        raise ValueError("the llvm-mca lower bound no longer contradicts the gate")
    iterations = mca["iterations"]
    total_cycles = mca["patchedProductionTotalCycles"]
    if not isinstance(iterations, int) or iterations <= 0:
        raise ValueError("llvm-mca iterations must be a positive integer")
    if not isinstance(total_cycles, int) or total_cycles <= 0:
        raise ValueError("llvm-mca total cycles must be a positive integer")
    patched_cycles = decimal(
        mca["patchedProductionCyclesPerBlock"],
        "stateOnlyKernel.llvmMCA.patchedProductionCyclesPerBlock",
    )
    if patched_cycles != Decimal(total_cycles) / Decimal(iterations):
        raise ValueError("the patched llvm-mca cycle average is inconsistent")
    state_only_cycles = decimal(
        mca["stateOnlyCyclesPerBlock"],
        "stateOnlyKernel.llvmMCA.stateOnlyCyclesPerBlock",
    )
    removed_cycles = patched_cycles - state_only_cycles
    recorded_removed_cycles = decimal(
        mca["nonStateCyclesRemovedByLowerBound"],
        "stateOnlyKernel.llvmMCA.nonStateCyclesRemovedByLowerBound",
    )
    if removed_cycles != recorded_removed_cycles or removed_cycles <= 0:
        raise ValueError("the llvm-mca removed-cycle budget is inconsistent")

    print(
        "WORKLOAD,boringssl_ns_per_block,state_only_ns_per_block,"
        "maximum_ratio,required_ns_per_block,shortfall_percent"
    )
    for measurement in evidence["measurements"]:
        boring_ssl = decimal(
            measurement["boringSSLNanosecondsPerBlock"],
            "measurements.boringSSLNanosecondsPerBlock",
        )
        state_only_ns = decimal(
            measurement["stateOnlyNanosecondsPerBlock"],
            "measurements.stateOnlyNanosecondsPerBlock",
        )
        maximum_ratio = boring_ssl / state_only_ns
        recorded_ratio = decimal(
            measurement["maximumRatio"],
            "measurements.maximumRatio",
        )
        if abs(maximum_ratio - recorded_ratio) > RATIO_TOLERANCE:
            raise ValueError("a recorded state-only ratio is inconsistent")
        if maximum_ratio >= required_ratio:
            raise ValueError("a state-only measurement no longer contradicts the gate")

        required_nanoseconds = boring_ssl / required_ratio
        shortfall_percent = (state_only_ns / required_nanoseconds - 1) * 100
        print(
            f"{measurement['workloadBytes']},"
            f"{boring_ssl:.6f},{state_only_ns:.6f},{maximum_ratio:.6f},"
            f"{required_nanoseconds:.6f},{shortfall_percent:.6f}"
        )

    block_workloads = {1024, 16384}
    production = {
        measurement["workloadBytes"]: measurement
        for measurement in evidence["patchedProduction"]
    }
    if set(production) != {64, 1024, 16384}:
        raise ValueError("the patched production workload set changed")
    for workload in block_workloads:
        lower_bound = decimal(
            production[workload]["pairedBootstrap95Lower"],
            "patchedProduction.pairedBootstrap95Lower",
        )
        upper_bound = decimal(
            production[workload]["pairedBootstrap95Upper"],
            "patchedProduction.pairedBootstrap95Upper",
        )
        if lower_bound >= required_ratio or upper_bound >= required_ratio:
            raise ValueError("a block workload no longer has a conclusive gate failure")

    print(
        "RESULT,native-single-stream-ceiling,"
        "state-only-bound-contradicts-1.10"
    )


if __name__ == "__main__":
    main()
