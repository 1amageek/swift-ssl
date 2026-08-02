import importlib.util
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_memory.py"
SPEC = importlib.util.spec_from_file_location("hpke_memory_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load HPKE memory benchmark runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class MemoryRunnerContractTests(unittest.TestCase):
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

    def test_expected_budgets_cover_every_workload(self) -> None:
        names = {workload["name"] for workload in runner.WORKLOADS}
        self.assertEqual(set(runner.EXPECTED_BUDGETS), names)

    def test_zero_allocation_x25519_budget_passes(self) -> None:
        derived = self.make_derived(
            allocation_calls=0,
            allocation_bytes=0,
            bulk_copy_bytes=0,
            malloc_calls=0,
            aligned_calls=0,
            free_calls=0,
        )
        self.assertEqual(runner.validate_budget("x25519-shared", derived), [])

    def test_budget_rejects_allocation_and_copy_drift(self) -> None:
        derived = self.make_derived(
            allocation_calls=4,
            allocation_bytes=167,
            bulk_copy_bytes=2_697,
            malloc_calls=3,
            aligned_calls=1,
            free_calls=4,
        )
        failures = runner.validate_budget("first-open-256", derived)
        self.assertTrue(any("allocationCalls" in failure for failure in failures))
        self.assertTrue(any("allocationBytes" in failure for failure in failures))
        self.assertTrue(any("bulkCopyBytes" in failure for failure in failures))

    def test_cross_workload_gate_rejects_payload_scaled_copy(self) -> None:
        results = {
            "first-open-256": {
                "derived": {
                    "perOperation": {
                        "allocationCalls": 3,
                        "allocationBytes": 166,
                        "bulkCopyBytes": 2_696,
                    }
                }
            },
            "first-open-1536": {
                "derived": {
                    "perOperation": {
                        "allocationCalls": 3,
                        "allocationBytes": 166,
                        "bulkCopyBytes": 3_976,
                    }
                }
            },
        }
        failures = runner.validate_cross_workload_budgets(results)
        self.assertEqual(len(failures), 1)
        self.assertIn("bulkCopyBytes scales with payload", failures[0])

    @staticmethod
    def make_derived(
        *,
        allocation_calls: int,
        allocation_bytes: int,
        bulk_copy_bytes: int,
        malloc_calls: int,
        aligned_calls: int,
        free_calls: int,
    ) -> dict[str, object]:
        return {
            "perOperation": {
                "allocationCalls": allocation_calls,
                "allocationBytes": allocation_bytes,
                "bulkCopyBytes": bulk_copy_bytes,
                "mallocCalls": malloc_calls,
                "alignedCalls": aligned_calls,
                "callocCalls": 0,
                "reallocCalls": 0,
                "memcpyBytes": 0,
                "freeCalls": free_calls,
            }
        }


if __name__ == "__main__":
    unittest.main()
