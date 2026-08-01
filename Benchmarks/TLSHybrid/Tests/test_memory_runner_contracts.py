import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNNER = ROOT / "Benchmarks/TLSHybrid/run_memory.py"
SPEC = importlib.util.spec_from_file_location("tls_hybrid_memory_runner", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load runner: {RUNNER}")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class MemoryRunnerContractTests(unittest.TestCase):
    def test_declares_every_hybrid_workload_budget(self) -> None:
        self.assertEqual(set(runner.WORKLOADS), set(runner.EXPECTED_BUDGETS))
        self.assertEqual(
            runner.EXPECTED_BUDGETS["x25519-public"],
            {"allocationCalls": 0, "allocationBytes": 0},
        )
        self.assertEqual(
            runner.EXPECTED_BUDGETS["x25519-shared"],
            {"allocationCalls": 0, "allocationBytes": 0},
        )

    def test_budget_rejects_dynamic_bulk_copy(self) -> None:
        values = {
            "allocationCalls": 0,
            "allocationBytes": 0,
            "bulkCopyBytes": 1,
            "callocCalls": 0,
            "reallocCalls": 0,
            "freeCalls": 0,
        }
        failures = runner.validate_budget(
            "x25519-public", {"perOperation": values}
        )
        self.assertTrue(any("bulkCopyBytes" in failure for failure in failures))

    def test_budget_rejects_allocation_imbalance(self) -> None:
        expected = runner.EXPECTED_BUDGETS["client-offer"]
        values = {
            **expected,
            "bulkCopyBytes": 0,
            "callocCalls": 0,
            "reallocCalls": 0,
            "freeCalls": expected["allocationCalls"] - 1,
        }
        failures = runner.validate_budget(
            "client-offer", {"perOperation": values}
        )
        self.assertTrue(any("imbalance" in failure for failure in failures))

    def test_runner_uses_clean_snapshot_and_atomic_output(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        self.assertIn("support.create_snapshot(ROOT, snapshot)", text)
        self.assertIn("source checkout changed during formal measurement", text)
        self.assertIn("os.replace(temporary_output, output)", text)
        self.assertIn('"--product",\n            "swift-ssl-tls-hybrid-benchmark"', text)


if __name__ == "__main__":
    unittest.main()
