#!/usr/bin/env python3
"""Contract tests for the standalone WASI SHA-256 benchmark runner."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_wasm_comparison.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_sha256_wasm_benchmark_runner",
    RUNNER_PATH,
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("Could not load the WASI benchmark runner")
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


class WASMRunnerContractTests(unittest.TestCase):
    def test_environment_discards_parent_build_overrides(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/tmp/untrusted",
                "CC": "/tmp/untrusted-clang",
                "SDKROOT": "/tmp/untrusted-sdk",
            },
            clear=False,
        ):
            environment = runner.inherited_environment()

        self.assertEqual(
            environment["PATH"],
            "/usr/bin:/bin:/usr/sbin:/sbin",
        )
        self.assertNotIn("CC", environment)
        self.assertNotIn("SDKROOT", environment)

    def test_parse_result_accepts_complete_result(self) -> None:
        result = runner.parse_result(
            "RESULT,123,456,"
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f\n"
        )

        self.assertEqual(result["measuredNanoseconds"], 123)
        self.assertEqual(result["checksum"], 456)

    def test_parse_result_rejects_extra_output(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_result(
                "diagnostic\n"
                "RESULT,123,456,"
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f\n"
            )

    def test_parse_result_rejects_nonpositive_duration(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.parse_result(
                "RESULT,0,456,"
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f\n"
            )

    def test_expected_digest_matches_fixed_fixture(self) -> None:
        self.assertEqual(
            runner.expected_digests(64, 1),
            [
                "9e38bbf2b200ff5c3b69de6d1f2f7066"
                "43a956e6eb70bbd9398c7f9c577d6db2"
            ],
        )

    def test_matching_results_rejects_checksum_difference(self) -> None:
        swift = {
            "checksum": 1,
            "digestHex": "00" * 32,
        }
        boringssl = {
            "checksum": 2,
            "digestHex": "00" * 32,
        }

        with self.assertRaises(runner.BenchmarkError):
            runner.require_matching_results(
                swift,
                boringssl,
                context="test",
            )

    def test_balanced_orders_are_reproducible(self) -> None:
        first = runner.balanced_orders(11, 42)
        second = runner.balanced_orders(11, 42)

        self.assertEqual(first, second)
        count_difference = abs(
            first.count("swift-boringssl")
            - first.count("boringssl-swift")
        )
        self.assertEqual(count_difference, 1)

    def test_bootstrap_interval_is_reproducible(self) -> None:
        first = runner.bootstrap_interval(
            [1.11, 1.12, 1.13, 1.14, 1.15],
            resamples=1_000,
            seed=7,
        )
        second = runner.bootstrap_interval(
            [1.11, 1.12, 1.13, 1.14, 1.15],
            resamples=1_000,
            seed=7,
        )

        self.assertEqual(first, second)
        self.assertLessEqual(first["lower"], first["upper"])

    def test_target_decision_uses_confidence_bound(self) -> None:
        self.assertEqual(
            runner.target_decision({"lower": 1.101, "upper": 1.2}),
            "pass",
        )
        self.assertEqual(
            runner.target_decision({"lower": 1.0, "upper": 1.099}),
            "fail",
        )
        self.assertEqual(
            runner.target_decision({"lower": 1.09, "upper": 1.11}),
            "inconclusive",
        )

    def test_selected_sdks_preserve_requested_scope(self) -> None:
        self.assertEqual(
            runner.selected_sdks("wasi"),
            (runner.WASI_SDK,),
        )
        self.assertEqual(
            runner.selected_sdks("embedded"),
            (runner.EMBEDDED_WASI_SDK,),
        )
        self.assertEqual(
            runner.selected_sdks("both"),
            (runner.WASI_SDK, runner.EMBEDDED_WASI_SDK),
        )


if __name__ == "__main__":
    unittest.main()
