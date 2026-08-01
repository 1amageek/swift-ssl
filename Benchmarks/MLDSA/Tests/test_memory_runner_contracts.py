import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "run_memory.py"
SPEC = importlib.util.spec_from_file_location("mldsa_memory_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class MemoryRunnerContractTests(unittest.TestCase):
    def observations(self, nonlinear: bool = False):
        result = []
        for iterations in RUNNER.ITERATION_COUNTS:
            counters = {
                name: 3 + iterations * (2 if name.endswith("Calls") else 16)
                for name in RUNNER.COUNTER_NAMES
            }
            if nonlinear and iterations == 10:
                counters["mallocCalls"] += 1
            for repetition in range(RUNNER.REPETITIONS):
                result.append(
                    {
                        "iterations": iterations,
                        "repetition": repetition,
                        "counters": dict(counters),
                        "checksum": iterations * 7,
                    }
                )
        return result

    def test_linear_counter_derivation(self):
        derived = RUNNER.derive_linear_counters(self.observations())
        self.assertEqual(derived["perOperation"]["mallocCalls"], 2)
        self.assertEqual(derived["fixedProcessOverhead"]["mallocCalls"], 3)

    def test_nonlinear_counter_is_rejected(self):
        with self.assertRaises(RUNNER.MeasurementError):
            RUNNER.derive_linear_counters(self.observations(nonlinear=True))

    def test_repeated_counter_difference_is_rejected(self):
        observations = self.observations()
        observations[1]["counters"]["mallocCalls"] += 1
        with self.assertRaises(RUNNER.MeasurementError):
            RUNNER.derive_linear_counters(observations)

    def test_copy_bytes_fail_budget(self):
        derived = {
            "perOperation": {
                "allocationCalls": 62,
                "allocationBytes": 59_248,
                "mallocCalls": 26,
                "callocCalls": 0,
                "reallocCalls": 0,
                "alignedCalls": 36,
                "freeCalls": 62,
                "bulkCopyCalls": 8,
                "bulkCopyBytes": 40_959,
            }
        }
        failures = RUNNER.validate_budget("mldsa65-sign", derived)
        self.assertTrue(any("bulkCopyBytes" in failure for failure in failures))

    def test_exact_verification_budget_passes(self):
        derived = {
            "perOperation": {
                "allocationCalls": 14,
                "allocationBytes": 31_712,
                "mallocCalls": 11,
                "callocCalls": 0,
                "reallocCalls": 0,
                "alignedCalls": 3,
                "freeCalls": 14,
                "bulkCopyCalls": 1,
                "bulkCopyBytes": 0,
            }
        }
        self.assertEqual(RUNNER.validate_budget("mldsa65-verify", derived), [])


if __name__ == "__main__":
    unittest.main()
