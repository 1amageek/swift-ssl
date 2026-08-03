#!/usr/bin/env python3
"""Contract tests for the standalone WASI SHA-256 memory runner."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


RUNNER_PATH = pathlib.Path(__file__).resolve().parents[1] / "run_wasm_memory.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_sha256_wasm_memory_runner",
    RUNNER_PATH,
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("Could not load the WASI SHA-256 memory runner")
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


def begin(name: str) -> dict[str, object]:
    return {"ph": "B", "name": name, "pid": 1, "ts": 0}


def end(name: str) -> dict[str, object]:
    return {"ph": "E", "name": name, "pid": 1, "ts": 1}


def scope_events(
    iterations: int,
    *,
    extra_names: tuple[str, ...] = (),
) -> list[dict[str, object]]:
    run_name = f"prefix{runner.RUN_SYMBOL_FRAGMENT}suffix"
    update_name = f"prefix{runner.UPDATE_SYMBOL_FRAGMENT}suffix"
    finalize_name = f"prefix{runner.FINALIZE_SYMBOL_FRAGMENT}suffix"
    events = [begin(run_name)]
    for _ in range(iterations):
        events.extend((begin(update_name), end(update_name)))
        events.extend((begin(finalize_name), end(finalize_name)))
    for name in extra_names:
        events.extend((begin(name), end(name)))
    events.append(end(run_name))
    return events


class WASMMemoryRunnerContractTests(unittest.TestCase):
    def test_profile_selects_scope_with_requested_iteration_count(self) -> None:
        events = scope_events(0) + scope_events(10)

        counters = runner.parse_measured_scope(
            events,
            expected_iterations=10,
        )

        self.assertEqual(counters["contextUpdateCalls"], 10)
        self.assertEqual(counters["contextFinalizeCalls"], 10)

    def test_profile_rejects_unbalanced_events(self) -> None:
        run_name = f"prefix{runner.RUN_SYMBOL_FRAGMENT}suffix"
        with self.assertRaises(runner.MemoryMeasurementError):
            runner.parse_measured_scope(
                [begin(run_name)],
                expected_iterations=1,
            )

    def test_profile_counts_allocation_and_copy_calls(self) -> None:
        events = scope_events(
            1,
            extra_names=(
                "malloc",
                "free",
                "swift_allocObject",
                "swift_deallocObject",
                "memcpy",
                "__swift_memcpy32_8",
            ),
        )

        counters = runner.parse_measured_scope(
            events,
            expected_iterations=1,
        )

        self.assertEqual(counters["libcAllocationCalls"], 1)
        self.assertEqual(counters["libcDeallocationCalls"], 1)
        self.assertEqual(counters["swiftAllocationCalls"], 1)
        self.assertEqual(counters["swiftDeallocationCalls"], 1)
        self.assertEqual(counters["bulkCopyFunctionCalls"], 1)
        self.assertEqual(counters["fixedCopyHelperCalls"], 1)
        self.assertEqual(counters["fixedCopyHelperBytes"], 32)

    def observations(self, *, nonlinear: bool = False):
        observations = []
        for iterations in runner.ITERATION_COUNTS:
            counters = {
                name: iterations
                if name in ("contextUpdateCalls", "contextFinalizeCalls")
                else 0
                for name in runner.COUNTER_NAMES
            }
            if nonlinear and iterations == 10:
                counters["libcAllocationCalls"] = 1
            for repetition in range(3):
                observations.append(
                    {
                        "iterations": iterations,
                        "repetition": repetition,
                        "counters": dict(counters),
                    }
                )
        return observations

    def test_linear_zero_allocation_budget_passes(self) -> None:
        derived = runner.derive_linear_counters(
            self.observations(),
            repetitions=3,
        )

        self.assertEqual(
            runner.validate_budget(derived, byte_count=1_048_577),
            [],
        )

    def test_nonlinear_counter_is_rejected(self) -> None:
        with self.assertRaises(runner.MemoryMeasurementError):
            runner.derive_linear_counters(
                self.observations(nonlinear=True),
                repetitions=3,
            )

    def test_budget_rejects_dynamic_copy(self) -> None:
        derived = runner.derive_linear_counters(
            self.observations(),
            repetitions=3,
        )
        derived["perOperation"]["bulkCopyFunctionCalls"] = 1

        failures = runner.validate_budget(derived, byte_count=1_048_576)

        self.assertTrue(
            any("bulkCopyFunctionCalls" in failure for failure in failures)
        )

    def test_expected_result_matches_fixed_fixture(self) -> None:
        result = runner.expected_result(64, 1)

        self.assertEqual(result["checksum"], 158)
        self.assertEqual(
            result["digestHex"],
            "9e38bbf2b200ff5c3b69de6d1f2f7066"
            "43a956e6eb70bbd9398c7f9c577d6db2",
        )

    def test_unique_symbol_resolution_supports_embedded_mangling(self) -> None:
        table = (
            "0000e805 l F CODE 0000407a "
            "$e14SSLCrypto13SHA256ContextV6updateyys4Span\n"
        )

        symbol = runner.resolve_unique_symbol(
            table,
            runner.UPDATE_SYMBOL_FRAGMENT,
        )

        self.assertTrue(symbol.startswith("$e14SSLCrypto"))

        with self.assertRaises(runner.MemoryMeasurementError):
            runner.resolve_unique_symbol(table + table, runner.UPDATE_SYMBOL_FRAGMENT)

    def test_profiled_result_accepts_only_wasmkit_completion_message(self) -> None:
        profile_path = pathlib.Path("/tmp/profile.json")
        result = runner.parse_profiled_result(
            "RESULT,123,456,"
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f\n"
            "Profile Completed: /tmp/profile.json can be viewed using "
            "https://ui.perfetto.dev/\n",
            profile_path,
        )

        self.assertEqual(result["measuredNanoseconds"], 123)

        with self.assertRaises(runner.MemoryMeasurementError):
            runner.parse_profiled_result(
                "RESULT,123,456,"
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f\n"
                "unexpected\n",
                profile_path,
            )


if __name__ == "__main__":
    unittest.main()
