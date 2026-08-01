import importlib.util
import random
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_comparison.py"
SPEC = importlib.util.spec_from_file_location("tls_hybrid_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load TLS hybrid benchmark runner")
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

    def test_client_record_requires_exact_lowercase_share(self) -> None:
        client_share = "ab" * 1_216
        self.assertEqual(
            runner.parse_client_record(f"CLIENT,{client_share}"),
            client_share,
        )
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_client_record(f"CLIENT,{client_share.upper()}")
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_client_record(f"CLIENT,{client_share[:-2]}")

    def test_server_record_requires_exact_share_and_secret_lengths(self) -> None:
        server_share = "cd" * 1_120
        secret = "ef" * 64
        self.assertEqual(
            runner.parse_server_record(f"SERVER,{server_share},{secret}"),
            (server_share, secret),
        )
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_server_record(f"SERVER,{server_share[:-2]},{secret}")
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_server_record(f"SERVER,{server_share},{secret[:-2]}")

    def test_secret_record_requires_exact_lowercase_secret(self) -> None:
        secret = "ab" * 64
        self.assertEqual(runner.parse_secret_record(f"SECRET,{secret}"), secret)
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_secret_record(f"SECRET,{secret.upper()}")

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
