import importlib.util
import os
import random
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_comparison.py"
SPEC = importlib.util.spec_from_file_location("mldsa_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load ML-DSA benchmark runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

MEMORY_RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_memory.py"
MEMORY_SPEC = importlib.util.spec_from_file_location(
    "mldsa_memory_runner", MEMORY_RUNNER_PATH
)
if MEMORY_SPEC is None or MEMORY_SPEC.loader is None:
    raise RuntimeError("could not load ML-DSA memory runner")
memory_runner = importlib.util.module_from_spec(MEMORY_SPEC)
MEMORY_SPEC.loader.exec_module(memory_runner)


class RunnerContractTests(unittest.TestCase):
    def test_parse_worker_result_accepts_exact_record(self) -> None:
        self.assertEqual(
            runner.parse_worker_result("RESULT,1234,5678\n", ""),
            {"nanoseconds": 1234, "checksum": 5678},
        )

    def test_parse_worker_result_rejects_extra_output(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_worker_result("RESULT,1234,5678\nextra\n", "")
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_worker_result("RESULT,1234,5678\n", "warning\n")

    def test_balanced_orders_are_equal_and_reproducible(self) -> None:
        first = runner.balanced_orders(30, random.Random(42))
        second = runner.balanced_orders(30, random.Random(42))
        self.assertEqual(first, second)
        self.assertEqual(first.count("swift-first"), 15)
        self.assertEqual(first.count("boringssl-first"), 15)

    def test_balanced_orders_reject_odd_count(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.balanced_orders(31, random.Random(42))

    def test_bootstrap_interval_contains_constant_median(self) -> None:
        lower, upper = runner.bootstrap_median_interval(
            [1.25] * 30,
            1_000,
            random.Random(17),
        )
        self.assertEqual(lower, 1.25)
        self.assertEqual(upper, 1.25)

    def test_fixture_record_requires_complete_parameter_set_lengths(self) -> None:
        for parameter_set in runner.PARAMETER_SETS:
            public_key = "01" * runner.PUBLIC_KEY_BYTES[parameter_set]
            signature = "02" * runner.SIGNATURE_BYTES[parameter_set]
            self.assertEqual(
                runner.parse_fixture_record(
                    f"FIXTURE,{public_key},{signature}", parameter_set
                ),
                (public_key, signature),
            )
            with self.assertRaises(runner.BenchmarkError):
                runner.parse_fixture_record(
                    f"FIXTURE,{public_key[:-2]},{signature}", parameter_set
                )

    def test_convergence_uses_latest_three_observations(self) -> None:
        self.assertFalse(runner.convergence_reached([100.0, 101.0]))
        self.assertTrue(runner.convergence_reached([200.0, 100.0, 102.0, 98.0]))
        self.assertFalse(runner.convergence_reached([100.0, 120.0, 90.0]))

    def test_code_block_selection_does_not_include_adjacent_symbols(self) -> None:
        disassembly = "_first_target:\n\tumin.8h\n_other:\n\tbranch\n"
        self.assertEqual(
            runner.code_blocks_containing(disassembly, "target"),
            ["_first_target:\n\tumin.8h"],
        )

    def test_executable_identity_preserves_invocation_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            invocation = Path(directory) / "tool-name"
            os.symlink("/bin/echo", invocation)
            identity = runner.executable_identity(invocation)
            self.assertEqual(identity["invocationPath"], str(invocation))
            self.assertEqual(identity["resolvedPath"], str(Path("/bin/echo").resolve()))

    def test_memory_budgets_cover_every_parameter_and_operation(self) -> None:
        expected = {
            f"mldsa{parameter_set}-{operation}"
            for parameter_set in memory_runner.PARAMETER_SETS
            for operation in ("keygen", "sign", "verify")
        }
        self.assertEqual(set(memory_runner.EXPECTED_BUDGETS), expected)


if __name__ == "__main__":
    unittest.main()
