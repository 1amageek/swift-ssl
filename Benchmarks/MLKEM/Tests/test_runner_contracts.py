import importlib.util
import os
import random
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_comparison.py"
SPEC = importlib.util.spec_from_file_location("mlkem_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load ML-KEM benchmark runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


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
        public_key = "01" * 1_184
        ciphertext = "02" * 1_088
        secret = "03" * 32
        self.assertEqual(
            runner.parse_fixture_record(
                f"FIXTURE,{public_key},{ciphertext},{secret}", 768
            ),
            (public_key, ciphertext, secret),
        )
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_fixture_record(
                f"FIXTURE,{public_key[:-2]},{ciphertext},{secret}", 768
            )

    def test_secret_record_requires_exact_lowercase_hex(self) -> None:
        secret = "ab" * 32
        self.assertEqual(runner.parse_secret_record(f"SECRET,{secret}"), secret)
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_secret_record(f"SECRET,{secret.upper()}")

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


if __name__ == "__main__":
    unittest.main()
