import importlib.util
import random
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_comparison.py"
SPEC = importlib.util.spec_from_file_location("hpke_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load HPKE benchmark runner")
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
            runner.parse_worker_result(" RESULT,1234,5678\n", "")
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_worker_result("RESULT,1234,5678\n", "warning\n")

    def test_validation_patterns_require_exact_lowercase_records(self) -> None:
        valid = (
            "ENCAPSULATION," + "ab" * 32,
            "CIPHERTEXT," + "cd" * 272,
            "PLAINTEXT," + "ef" * 256,
        )
        for record, pattern in zip(valid, runner.VALIDATION_PATTERNS):
            self.assertIsNotNone(pattern.fullmatch(record))
            self.assertIsNone(pattern.fullmatch(record.upper()))

    def test_workload_matrix_is_fixed_and_unique(self) -> None:
        names = [workload["name"] for workload in runner.WORKLOADS]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            names,
            [
                "x25519-shared",
                "recipient-setup",
                "first-open-256",
                "first-open-1536",
            ],
        )

    def test_codegen_symbol_gate_uses_release_stable_routes(self) -> None:
        self.assertEqual(
            runner.REQUIRED_SWIFT_SYMBOLS,
            ("HPKEX25519", "X25519FieldElement"),
        )

    def test_codegen_gate_distinguishes_direct_and_emulated_pmull(self) -> None:
        disassembly = "pmull.1q v0, v1, v2\npmull.8h v3, v4, v5\n"
        self.assertEqual(len(runner.DIRECT_PMULL_PATTERN.findall(disassembly)), 1)
        self.assertEqual(len(runner.BYTE_PMULL_PATTERN.findall(disassembly)), 1)

    def test_balanced_orders_are_equal_and_reproducible(self) -> None:
        first = runner.balanced_orders(30, random.Random(42))
        second = runner.balanced_orders(30, random.Random(42))
        self.assertEqual(first, second)
        self.assertEqual(first.count("swift-first"), 15)
        self.assertEqual(first.count("boringssl-first"), 15)

    def test_convergence_uses_latest_three_observations(self) -> None:
        self.assertFalse(runner.convergence_reached([100.0, 101.0]))
        self.assertTrue(runner.convergence_reached([200.0, 100.0, 102.0, 98.0]))
        self.assertFalse(runner.convergence_reached([100.0, 120.0, 90.0]))

    def test_bootstrap_interval_contains_constant_median(self) -> None:
        lower, upper = runner.bootstrap_median_interval(
            [1.12] * 30,
            1_000,
            random.Random(17),
        )
        self.assertEqual(lower, 1.12)
        self.assertEqual(upper, 1.12)


if __name__ == "__main__":
    unittest.main()
