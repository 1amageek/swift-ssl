#!/usr/bin/env python3
"""Adversarial contract tests for the standalone SHA-256 benchmark runner."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_comparison.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "swift_ssl_sha256_benchmark_runner",
    RUNNER_PATH,
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("Could not load the benchmark runner")
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


class RunnerContractTests(unittest.TestCase):
    def test_environment_discards_parent_path_and_build_overrides(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/tmp/untrusted-shims",
                "CC": "/tmp/untrusted-clang",
                "SDKROOT": "/tmp/untrusted-sdk",
                "SWIFT_EXEC": "/tmp/untrusted-swift",
            },
            clear=False,
        ):
            environment = runner.sanitized_environment()

        self.assertEqual(
            environment["PATH"],
            "/usr/bin:/bin:/usr/sbin:/sbin",
        )
        self.assertNotIn("CC", environment)
        self.assertNotIn("SDKROOT", environment)
        self.assertNotIn("SWIFT_EXEC", environment)
        self.assertEqual(
            runner.sanitized_environment(
                {"SDKROOT": "/trusted/MacOSX27.0.sdk"}
            )["SDKROOT"],
            "/trusted/MacOSX27.0.sdk",
        )

    def test_swift_contract_rejects_unoptimized_benchmark_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            swift_source = Path(temporary_directory) / "source"
            swift_scratch = Path(temporary_directory) / "scratch"
            response_paths = self.create_swift_source_lists(
                swift_source,
                swift_scratch,
            )
            log = "\n".join(
                [
                    self.swift_command(
                        "SwiftSSLCore",
                        response_path=response_paths["SwiftSSLCore"],
                    ),
                    self.swift_command(
                        "SwiftSSLCrypto",
                        response_path=response_paths["SwiftSSLCrypto"],
                    ),
                    self.swift_command(
                        "SwiftSSLSHA256Benchmark",
                        optimization="-Onone",
                        response_path=response_paths[
                            "SwiftSSLSHA256Benchmark"
                        ],
                    ),
                    self.swift_command("UnrelatedOptimizedModule"),
                ]
            )
            completed = subprocess.CompletedProcess(
                args=["swift", "build"],
                returncode=0,
                stdout=log,
                stderr="",
            )

            with self.assertRaisesRegex(
                runner.BenchmarkError,
                "must use exactly one -O",
            ):
                runner.require_swift_build_contract(
                    completed=completed,
                    toolchain={
                        "swiftCompiler": "/trusted/swiftc",
                        "macOSSDKPath": "/trusted/SDK",
                    },
                    swift_source=swift_source,
                    swift_scratch=swift_scratch,
                )

    def test_swift_contract_binds_source_list_response_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            swift_source = Path(temporary_directory) / "source"
            swift_scratch = Path(temporary_directory) / "scratch"
            response_paths = self.create_swift_source_lists(
                swift_source,
                swift_scratch,
            )
            log = "\n".join(
                self.swift_command(
                    module_name,
                    response_path=response_paths[module_name],
                )
                for module_name in (
                    "SwiftSSLCore",
                    "SwiftSSLCrypto",
                    "SwiftSSLSHA256Benchmark",
                )
            )
            completed = subprocess.CompletedProcess(
                args=["swift", "build"],
                returncode=0,
                stdout=log,
                stderr="",
            )
            toolchain = {
                "swiftCompiler": "/trusted/swiftc",
                "macOSSDKPath": "/trusted/SDK",
            }

            result = runner.require_swift_build_contract(
                completed=completed,
                toolchain=toolchain,
                swift_source=swift_source,
                swift_scratch=swift_scratch,
            )

            self.assertEqual(
                set(result["validatedSourceLists"]),
                {
                    "SwiftSSLCore",
                    "SwiftSSLCrypto",
                    "SwiftSSLSHA256Benchmark",
                },
            )
            with response_paths["SwiftSSLCore"].open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write("-Onone\n")
            with self.assertRaises(runner.BenchmarkError):
                runner.require_swift_build_contract(
                    completed=completed,
                    toolchain=toolchain,
                    swift_source=swift_source,
                    swift_scratch=swift_scratch,
                )

    def test_swift_contract_rejects_vfs_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            swift_source = Path(temporary_directory) / "source"
            swift_scratch = Path(temporary_directory) / "scratch"
            response_paths = self.create_swift_source_lists(
                swift_source,
                swift_scratch,
            )
            commands = [
                self.swift_command(
                    module_name,
                    response_path=response_paths[module_name],
                )
                for module_name in (
                    "SwiftSSLCore",
                    "SwiftSSLCrypto",
                    "SwiftSSLSHA256Benchmark",
                )
            ]
            commands[1] += " -vfsoverlay /tmp/untrusted-overlay.yaml"
            completed = subprocess.CompletedProcess(
                args=["swift", "build"],
                returncode=0,
                stdout="\n".join(commands),
                stderr="",
            )

            with self.assertRaisesRegex(
                runner.BenchmarkError,
                "pinned Swift command shape",
            ):
                runner.require_swift_build_contract(
                    completed=completed,
                    toolchain={
                        "swiftCompiler": "/trusted/swiftc",
                        "macOSSDKPath": "/trusted/SDK",
                    },
                    swift_source=swift_source,
                    swift_scratch=swift_scratch,
                )

    def test_swift_contract_accepts_resolved_swiftc_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            compiler_directory = root / "toolchain/usr/bin"
            compiler_directory.mkdir(parents=True)
            swift_driver = compiler_directory / "swift-driver"
            swift_driver.write_bytes(b"synthetic compiler")
            swiftc = compiler_directory / "swiftc"
            swiftc.symlink_to(swift_driver)
            swift_source = root / "source"
            swift_scratch = root / "scratch"
            response_paths = self.create_swift_source_lists(
                swift_source,
                swift_scratch,
            )
            completed = subprocess.CompletedProcess(
                args=["swift", "build"],
                returncode=0,
                stdout="\n".join(
                    self.swift_command(
                        module_name,
                        response_path=response_paths[module_name],
                        compiler=str(swiftc),
                    )
                    for module_name in (
                        "SwiftSSLCore",
                        "SwiftSSLCrypto",
                        "SwiftSSLSHA256Benchmark",
                    )
                ),
                stderr="",
            )

            result = runner.require_swift_build_contract(
                completed=completed,
                toolchain={
                    "swiftCompiler": str(swift_driver.resolve()),
                    "macOSSDKPath": "/trusted/SDK",
                },
                swift_source=swift_source,
                swift_scratch=swift_scratch,
            )

            self.assertTrue(result["exactCommandShapeRequired"])

    def test_boringssl_contract_rejects_unoptimized_crypto_object(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        compile_database[2] = self.boringssl_compile_entry(
            "/source/crypto/fipsmodule/bcm.cc",
            optimization="-O1",
        )

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_accepts_complete_arm64_asm_build(self) -> None:
        result = runner.require_boringssl_build_contract(
            compile_database=self.valid_boringssl_compile_database(),
            cmake_cache=self.boringssl_cmake_cache(),
            toolchain=self.boringssl_toolchain(),
            swift_source=Path("/source"),
            boringssl_source=Path("/source"),
            boringssl_build=Path("/build"),
        )

        self.assertTrue(result["assemblyEnabled"])
        self.assertEqual(
            len(result["validatedRequiredSources"]),
            5,
        )

    def test_boringssl_contract_rejects_later_bare_optimization(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[2]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("-O")

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_assembly_disable_definition(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[0]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("-DOPENSSL_NO_ASM=0")

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_function_like_assembly_disable(
        self,
    ) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[0]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("-DOPENSSL_NO_ASM()")

        with self.assertRaisesRegex(
            runner.BenchmarkError,
            "disabled assembly",
        ):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_external_object_output(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[2]["arguments"]
        self.assertIsInstance(arguments, list)
        output_index = arguments.index("-o")
        arguments[output_index + 1] = "/tmp/untrusted.o"

        with self.assertRaisesRegex(
            runner.BenchmarkError,
            "outside the fresh build root",
        ):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_unexpected_build_directory(
        self,
    ) -> None:
        compile_database = self.valid_boringssl_compile_database()
        compile_database[2]["directory"] = "/tmp/untrusted-build"

        with self.assertRaisesRegex(
            runner.BenchmarkError,
            "unexpected build directory",
        ):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_response_file(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[2]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("@/tmp/untrusted-flags.rsp")

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_clang_config_file(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[2]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("--config=/tmp/untrusted-flags.cfg")

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_profile_instrumentation(self) -> None:
        compile_database = self.valid_boringssl_compile_database()
        arguments = compile_database[2]["arguments"]
        self.assertIsInstance(arguments, list)
        arguments.append("-fprofile-arcs")

        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=compile_database,
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/source"),
                boringssl_source=Path("/source"),
                boringssl_build=Path("/build"),
            )

    def test_boringssl_contract_rejects_external_source_roots(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.require_boringssl_build_contract(
                compile_database=self.valid_boringssl_compile_database(),
                cmake_cache=self.boringssl_cmake_cache(),
                toolchain=self.boringssl_toolchain(),
                swift_source=Path("/trusted/swift"),
                boringssl_source=Path("/trusted/boringssl"),
                boringssl_build=Path("/build"),
            )

    def test_direct_call_contract_rejects_unvalidated_allocation(self) -> None:
        instructions = [
            (0x100, "bl _$sSHA256ContextV6update", ""),
            (0x104, "bl _$sSHA256ContextV15finalizeInPlace", ""),
            (0x108, "bl _swift_allocObject", ""),
        ]

        with self.assertRaises(runner.BenchmarkError):
            runner.validate_direct_call_contract(
                instructions,
                label="synthetic timed loop",
                required_calls=(
                    ("update", "SHA256ContextV6update", 1),
                    ("finalize", "SHA256ContextV15finalizeInPlace", 1),
                ),
            )

    def test_direct_call_contract_rejects_external_branch_transfer(self) -> None:
        instructions = [
            (0x100, "bl _$sSHA256ContextV6update", ""),
            (0x104, "bl _$sSHA256ContextV15finalizeInPlace", ""),
            (0x108, "b _swift_allocObject", ""),
        ]

        with self.assertRaises(runner.BenchmarkError):
            runner.validate_direct_call_contract(
                instructions,
                label="synthetic timed loop",
                required_calls=(
                    ("update", "SHA256ContextV6update", 1),
                    ("finalize", "SHA256ContextV15finalizeInPlace", 1),
                ),
            )

    def test_direct_call_contract_rejects_conditional_external_branch(
        self,
    ) -> None:
        instructions = [
            (0x100, "bl _$sSHA256ContextV6update", ""),
            (0x104, "bl _$sSHA256ContextV15finalizeInPlace", ""),
            (0x108, "b.eq _external_helper", ""),
        ]

        with self.assertRaises(runner.BenchmarkError):
            runner.validate_direct_call_contract(
                instructions,
                label="synthetic timed loop",
                required_calls=(
                    ("update", "SHA256ContextV6update", 1),
                    ("finalize", "SHA256ContextV15finalizeInPlace", 1),
                ),
            )

    def test_direct_call_contract_rejects_authenticated_transfers(self) -> None:
        for transfer in (
            "blraa x8, x9",
            "braa x8, x9",
            "bc.eq _external_helper",
        ):
            with self.subTest(transfer=transfer):
                instructions = [
                    (0x100, "bl _$sSHA256ContextV6update", ""),
                    (0x104, "bl _$sSHA256ContextV15finalizeInPlace", ""),
                    (0x108, transfer, ""),
                ]

                with self.assertRaises(runner.BenchmarkError):
                    runner.validate_direct_call_contract(
                        instructions,
                        label="synthetic timed loop",
                        required_calls=(
                            ("update", "SHA256ContextV6update", 1),
                            (
                                "finalize",
                                "SHA256ContextV15finalizeInPlace",
                                1,
                            ),
                        ),
                    )

    def test_instruction_classification_covers_authenticated_returns(
        self,
    ) -> None:
        for instruction in ("retaa", "retab", "eretaa", "eretab", "drps"):
            with self.subTest(instruction=instruction):
                self.assertTrue(runner.is_return_instruction(instruction))

    def test_backedge_detection_includes_unconditional_branch(self) -> None:
        self.assertEqual(
            runner.find_backedges(
                [
                    (0x100, "nop", ""),
                    (0x104, "b 0x100", ""),
                ],
                function_start=0x100,
            ),
            [(0x100, 0x104)],
        )

    def test_multiblock_gate_rejects_vector_reload_inside_loop(self) -> None:
        kernel = self.synthetic_kernel(extra_loop_instruction="ldr q2, [x9]")
        context = self.synthetic_context_update()
        finalize = self.synthetic_finalize()

        with mock.patch.object(
            runner,
            "load_macho_text_function",
            side_effect=[kernel, context, finalize],
        ):
            with self.assertRaises(runner.BenchmarkError):
                runner.analyze_sha256_multiblock_codegen(
                    Path("/synthetic/worker"),
                    toolchain={},
                )

    def test_multiblock_gate_rejects_unlisted_vector_memory_opcode(
        self,
    ) -> None:
        kernel = self.synthetic_kernel(
            extra_loop_instruction="ldnp q2, q3, [x9]"
        )
        context = self.synthetic_context_update()
        finalize = self.synthetic_finalize()

        with mock.patch.object(
            runner,
            "load_macho_text_function",
            side_effect=[kernel, context, finalize],
        ):
            with self.assertRaises(runner.BenchmarkError):
                runner.analyze_sha256_multiblock_codegen(
                    Path("/synthetic/worker"),
                    toolchain={},
                )

    def test_multiblock_gate_rejects_scalar_simd_memory_aliases(self) -> None:
        for memory_instruction in ("ldr h2, [x9]", "ldr b2, [x9]"):
            with self.subTest(memory_instruction=memory_instruction):
                kernel = self.synthetic_kernel(
                    extra_loop_instruction=memory_instruction
                )
                context = self.synthetic_context_update()
                finalize = self.synthetic_finalize()

                with mock.patch.object(
                    runner,
                    "load_macho_text_function",
                    side_effect=[kernel, context, finalize],
                ):
                    with self.assertRaises(runner.BenchmarkError):
                        runner.analyze_sha256_multiblock_codegen(
                            Path("/synthetic/worker"),
                            toolchain={},
                        )

    def test_multiblock_gate_rejects_duplicate_state_store(self) -> None:
        kernel = self.synthetic_kernel(extra_loop_instruction="nop")
        context = self.synthetic_context_update()
        context["instructions"].append(
            (0x550, "stp q0, q1, [x20]", "stp q0, q1, [x20]")
        )
        finalize = self.synthetic_finalize()

        with mock.patch.object(
            runner,
            "load_macho_text_function",
            side_effect=[kernel, context, finalize],
        ):
            with self.assertRaises(runner.BenchmarkError):
                runner.analyze_sha256_multiblock_codegen(
                    Path("/synthetic/worker"),
                    toolchain={},
                )

    def test_multiblock_gate_rejects_alternative_state_stores(self) -> None:
        for store_instruction in (
            "stnp q0, q1, [x20]",
            "str q0, [x21]",
        ):
            with self.subTest(store_instruction=store_instruction):
                kernel = self.synthetic_kernel(extra_loop_instruction="nop")
                context = self.synthetic_context_update()
                context["instructions"].append(
                    (0x550, store_instruction, store_instruction)
                )
                finalize = self.synthetic_finalize()

                with mock.patch.object(
                    runner,
                    "load_macho_text_function",
                    side_effect=[kernel, context, finalize],
                ):
                    with self.assertRaises(runner.BenchmarkError):
                        runner.analyze_sha256_multiblock_codegen(
                            Path("/synthetic/worker"),
                            toolchain={},
                        )

    def test_exploratory_convergence_rejects_nonquiescent_host(self) -> None:
        with mock.patch.object(
            runner,
            "collect_quiescence",
            return_value={"synthetic": True},
        ), mock.patch.object(
            runner,
            "quiescence_reasons",
            return_value=["synthetic load"],
        ):
            with self.assertRaises(runner.BenchmarkError):
                runner.verify_timing_convergence(
                    Path("/synthetic/swift"),
                    Path("/synthetic/boringssl"),
                    byte_count=64,
                    iterations=1,
                    warmup_iterations=1,
                    timeout_seconds=1,
                )

    def test_quiescence_rejects_unavailable_process_state(self) -> None:
        observation = {
            "oneMinuteLoadPerLogicalCPU": 0.0,
            "activeBuildProcesses": None,
            "powerState": "Now drawing from 'AC Power'",
            "powerMode": 0,
            "thermalState": (
                "No thermal warning level has been recorded\n"
                "No performance warning level has been recorded"
            ),
        }

        self.assertIn(
            "build process state is unavailable",
            runner.quiescence_reasons(observation),
        )

    def test_build_process_detection_covers_versioned_compilers(self) -> None:
        self.assertTrue(runner.is_build_process_name("clang-21"))
        self.assertTrue(runner.is_build_process_name("(ld)"))
        self.assertTrue(runner.is_build_process_name("swift-driver"))
        self.assertTrue(runner.is_build_process_name("swiftc-6.4"))
        self.assertTrue(runner.is_build_process_name("swift-frontend-6.4"))
        self.assertTrue(runner.is_build_process_name("swift-driver-6.4"))
        self.assertTrue(runner.is_build_process_name("swift-build-6.4"))
        self.assertFalse(runner.is_build_process_name("python3"))

    def test_build_process_detection_excludes_sourcekit_plugin_server(
        self,
    ) -> None:
        self.assertFalse(runner.is_build_process_name("swift-plugin-server"))
        self.assertFalse(runner.is_build_process_name("(swift-plugin-server)"))

    def test_formal_snapshot_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.write_text("trusted", encoding="utf-8")
            (root / "link").symlink_to(target)

            with self.assertRaises(runner.BenchmarkError):
                runner.reject_source_snapshot_symlinks(root)

    def test_tool_binding_rejects_retargeted_invocation_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            link = Path(temporary_directory) / "tool"
            link.symlink_to("/bin/echo")
            initial = runner.executable_metadata(link)
            link.unlink()
            link.symlink_to("/usr/bin/false")

            completed = runner.run_command(
                [str(link), "resolved execution"],
                executable_path=initial["path"],
            )
            self.assertEqual(completed.stdout.strip(), "resolved execution")
            with self.assertRaises(runner.BenchmarkError):
                runner.verify_executable_metadata_unchanged({"tool": initial})

    def test_macho_contract_rejects_unexpected_linked_sdk(self) -> None:
        responses = [
            subprocess.CompletedProcess(
                args=["lipo"],
                returncode=0,
                stdout=f"{runner.EXPECTED_ARCHITECTURE}\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["vtool"],
                returncode=0,
                stdout=(
                    "Load command 0\n"
                    "      cmd LC_BUILD_VERSION\n"
                    " platform MACOS\n"
                    f"    minos {runner.DEPLOYMENT_TARGET}\n"
                    "      sdk 99.0\n"
                ),
                stderr="",
            ),
        ]
        with mock.patch.object(
            runner,
            "run_command",
            side_effect=responses,
        ):
            with self.assertRaises(runner.BenchmarkError):
                runner.collect_macho_metadata(
                    Path("/synthetic/worker"),
                    toolchain={
                        "developerDirectory": "/trusted/Xcode",
                        "lipo": {
                            "invocationPath": "/trusted/lipo",
                            "path": "/trusted/llvm-lipo",
                        },
                        "vtool": {
                            "invocationPath": "/trusted/vtool",
                            "path": "/trusted/llvm-vtool",
                        },
                    },
                )

    def test_storage_contract_rejects_insufficient_capacity(self) -> None:
        with self.assertRaises(runner.BenchmarkError):
            runner.require_available_storage(
                {
                    "artifactOutput": {
                        "availableBytes": (
                            runner.MINIMUM_BUILD_AVAILABLE_BYTES - 1
                        )
                    }
                },
                minimum_available_bytes=runner.MINIMUM_BUILD_AVAILABLE_BYTES,
                phase="synthetic start",
            )

    def test_worker_output_rejects_extra_stdout(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["worker"],
            returncode=0,
            stdout=("noise\nRESULT,1,0," + "00" * 32 + "\n"),
            stderr="",
        )
        with mock.patch.object(runner, "run_command", return_value=completed):
            with self.assertRaises(runner.BenchmarkError):
                runner.run_worker(
                    Path("/synthetic/worker"),
                    byte_count=64,
                    iterations=1,
                    warmup_iterations=0,
                    timeout_seconds=1,
                )

    def test_validation_output_rejects_surrounding_whitespace(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["worker"],
            returncode=0,
            stdout=("DIGEST,0," + "00" * 32 + " \n"),
            stderr="",
        )
        with mock.patch.object(runner, "run_command", return_value=completed):
            with self.assertRaises(runner.BenchmarkError):
                runner.run_validation_worker(
                    Path("/synthetic/worker"),
                    byte_count=64,
                    timeout_seconds=1,
                )

    def test_atomic_artifact_write_does_not_clobber_existing_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "artifact.json"
            output_path.write_text("existing", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                runner.write_json_atomically(output_path, {"status": "new"})

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "existing",
            )

    def test_symlink_loop_output_path_returns_invalid_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            loop = Path(temporary_directory) / "loop"
            loop.symlink_to(loop, target_is_directory=True)

            result = runner.main(
                [
                    "--boringssl-source",
                    temporary_directory,
                    "--output",
                    str(loop / "artifact.json"),
                ]
            )

            self.assertEqual(result, 2)

    def test_unexpected_exception_writes_invalid_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "invalid.json"
            with mock.patch.object(
                runner,
                "git_metadata",
                side_effect=OSError("synthetic I/O failure"),
            ), mock.patch.object(
                runner,
                "require_available_storage",
            ):
                result = runner.main(
                    [
                        "--boringssl-source",
                        temporary_directory,
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(result, 2)
            artifact = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "invalid")
            self.assertEqual(artifact["error"]["type"], "OSError")
            self.assertFalse(artifact["error"]["expectedContractFailure"])

    def test_artifact_write_failure_still_returns_invalid_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with mock.patch.object(
                runner,
                "git_metadata",
                side_effect=OSError("synthetic source failure"),
            ), mock.patch.object(
                runner,
                "require_available_storage",
            ), mock.patch.object(
                runner,
                "write_json_atomically",
                side_effect=OSError("synthetic no space"),
            ):
                result = runner.main(
                    [
                        "--boringssl-source",
                        temporary_directory,
                        "--output",
                        str(Path(temporary_directory) / "unwritable.json"),
                    ]
                )

            self.assertEqual(result, 2)

    def test_boringssl_link_contract_binds_fresh_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            build_directory = Path(temporary_directory)
            driver_object = (
                build_directory
                / (
                    "CMakeFiles/boringssl-sha256-benchmark.dir/"
                    "SHA256Benchmark.cpp.o"
                )
            )
            crypto_archive = build_directory / "boringssl/libcrypto.a"
            driver_object.parent.mkdir(parents=True)
            crypto_archive.parent.mkdir(parents=True)
            driver_object.write_bytes(b"driver")
            crypto_archive.write_bytes(b"archive")
            command = " ".join(
                [
                    "/trusted/clang++",
                    "--driver-mode=g++",
                    "-O3",
                    "-DNDEBUG",
                    "-arch",
                    runner.EXPECTED_ARCHITECTURE,
                    "-isysroot",
                    "/trusted/SDK",
                    f"-mmacosx-version-min={runner.DEPLOYMENT_TARGET}",
                    "-Wl,-search_paths_first",
                    "-Wl,-headerpad_max_install_names",
                    (
                        "CMakeFiles/boringssl-sha256-benchmark.dir/"
                        "SHA256Benchmark.cpp.o"
                    ),
                    "-o",
                    "boringssl-sha256-benchmark",
                    "boringssl/libcrypto.a",
                ]
            )
            completed = subprocess.CompletedProcess(
                args=["cmake", "--build"],
                returncode=0,
                stdout=f"[1/1] {command}\n",
                stderr="",
            )

            result = runner.require_boringssl_link_contract(
                completed=completed,
                build_directory=build_directory,
                toolchain=self.boringssl_toolchain(),
            )

            self.assertTrue(result["passed"])
            self.assertEqual(
                result["inputs"]["driverObject"]["path"],
                str(driver_object.resolve()),
            )
            poisoned_completed = subprocess.CompletedProcess(
                args=["cmake", "--build"],
                returncode=0,
                stdout=(
                    "[1/1] "
                    + command.replace(
                        (
                            "CMakeFiles/boringssl-sha256-benchmark.dir/"
                            "SHA256Benchmark.cpp.o"
                        ),
                        (
                            "CMakeFiles/boringssl-sha256-benchmark.dir/"
                            "SHA256Benchmark.cpp.o -L/tmp/untrusted -lcrypto"
                        ),
                    )
                    + "\n"
                ),
                stderr="",
            )
            with self.assertRaises(runner.BenchmarkError):
                runner.require_boringssl_link_contract(
                    completed=poisoned_completed,
                    build_directory=build_directory,
                    toolchain=self.boringssl_toolchain(),
                )

    def test_boringssl_dependency_contract_accepts_trusted_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = self.create_dependency_fixture(
                Path(temporary_directory)
            )

            result = runner.require_boringssl_dependency_contract(
                completed=fixture["completed"],
                build_directory=fixture["build"],
                compile_outputs=fixture["compile_outputs"],
                required_object_outputs=fixture["required_outputs"],
                boringssl_source=fixture["boringssl_source"],
                driver_source=fixture["driver_source"],
                sdk_root=fixture["sdk_root"],
                clang_resource_directory=fixture["clang_resource"],
            )

            self.assertTrue(result["passed"])
            self.assertEqual(result["disallowedDependencyCount"], 0)
            self.assertTrue(
                runner.verify_dependency_content_manifest_unchanged(
                    result
                )["unchanged"]
            )
            fixture["sdk_header"].write_text("changed", encoding="utf-8")
            with self.assertRaises(runner.BenchmarkError):
                runner.verify_dependency_content_manifest_unchanged(result)

    def test_boringssl_dependency_contract_rejects_external_header(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fixture = self.create_dependency_fixture(root)
            external_header = root / "external/untrusted.h"
            external_header.parent.mkdir()
            external_header.write_text("untrusted", encoding="utf-8")
            poisoned_stdout = fixture["completed"].stdout.replace(
                str(fixture["sdk_header"]),
                str(external_header),
            )
            poisoned_completed = subprocess.CompletedProcess(
                args=["ninja", "-t", "deps"],
                returncode=0,
                stdout=poisoned_stdout,
                stderr="",
            )

            with self.assertRaisesRegex(
                runner.BenchmarkError,
                "outside the trusted roots",
            ):
                runner.require_boringssl_dependency_contract(
                    completed=poisoned_completed,
                    build_directory=fixture["build"],
                    compile_outputs=fixture["compile_outputs"],
                    required_object_outputs=fixture["required_outputs"],
                    boringssl_source=fixture["boringssl_source"],
                    driver_source=fixture["driver_source"],
                    sdk_root=fixture["sdk_root"],
                    clang_resource_directory=fixture["clang_resource"],
                )

    def test_boringssl_dependency_contract_requires_compile_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fixture = self.create_dependency_fixture(root)
            compile_source = fixture["compile_outputs"][0]["source"]
            poisoned_stdout = fixture["completed"].stdout.replace(
                f"    {compile_source}\n",
                f"    {fixture['sdk_header']}\n",
            )
            poisoned_completed = subprocess.CompletedProcess(
                args=["ninja", "-t", "deps"],
                returncode=0,
                stdout=poisoned_stdout,
                stderr="",
            )

            with self.assertRaisesRegex(
                runner.BenchmarkError,
                "exact compile source",
            ):
                runner.require_boringssl_dependency_contract(
                    completed=poisoned_completed,
                    build_directory=fixture["build"],
                    compile_outputs=fixture["compile_outputs"],
                    required_object_outputs=fixture["required_outputs"],
                    boringssl_source=fixture["boringssl_source"],
                    driver_source=fixture["driver_source"],
                    sdk_root=fixture["sdk_root"],
                    clang_resource_directory=fixture["clang_resource"],
                )

    def test_odd_sample_count_is_rejected(self) -> None:
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as context:
                runner.main(
                    [
                        "--boringssl-source",
                        "/synthetic/boringssl",
                        "--samples",
                        "31",
                    ]
                )
        self.assertEqual(context.exception.code, 2)

    @staticmethod
    def swift_command(
        module_name: str,
        *,
        optimization: str = "-O",
        response_path: Path | None = None,
        compiler: str = "/trusted/swiftc",
    ) -> str:
        if response_path is None:
            return (
                f"builtin-SwiftDriver -- {compiler} -module-name "
                f"{module_name} {optimization}"
            )
        release_root = response_path.resolve().parent.parent
        modules_root = release_root / "Modules"
        module_build_root = release_root / f"{module_name}.build"
        compiler_usr_root = Path(compiler).resolve().parents[1]
        testing_library_root = (
            compiler_usr_root / "lib/swift/macosx/testing"
        )
        testing_plugin_root = (
            compiler_usr_root / "lib/swift/host/plugins/testing"
        )
        sdk_path = Path("/trusted/SDK").resolve()
        platform_developer_root = sdk_path.parents[1]
        platform_framework_root = (
            platform_developer_root / "Library/Frameworks"
        )
        platform_library_root = platform_developer_root / "usr/lib"
        feature_names = [
            "NonescapableTypes",
            "LifetimeDependence",
            "InoutLifetimeDependence",
            "LifetimeDependenceMutableAccessors",
            "Lifetimes",
            "Extern",
        ]
        if module_name == "SwiftSSLCrypto":
            feature_names.append("BuiltinModule")
        if module_name == "SwiftSSLCore":
            feature_names.append("Volatile")
        arguments = [
            compiler,
            "-module-name",
            module_name,
            "-emit-dependencies",
            "-emit-module",
            "-emit-module-path",
            str(modules_root / f"{module_name}.swiftmodule"),
            "-output-file-map",
            str(module_build_root / "output-file-map.json"),
        ]
        if module_name != "SwiftSSLSHA256Benchmark":
            arguments.append("-parse-as-library")
        arguments.extend(
            [
                "-whole-module-optimization",
                "-num-threads",
                str(os.cpu_count()),
                "-c",
                f"@{response_path.resolve()}",
                "-I",
                str(modules_root),
                "-target",
                runner.SWIFT_COMPILE_TARGET,
                "-v",
                "-whole-module-optimization",
                "-num-threads",
                str(os.cpu_count()),
                "-serialize-diagnostics",
                optimization,
                "-j2",
                "-DSWIFT_PACKAGE",
                "-DSWIFT_MODULE_RESOURCE_BUNDLE_UNAVAILABLE",
                "-module-cache-path",
                str(release_root / "ModuleCache"),
                "-parseable-output",
            ]
        )
        if module_name == "SwiftSSLSHA256Benchmark":
            arguments.extend(
                [
                    "-Xfrontend",
                    "-entry-point-function-name",
                    "-Xfrontend",
                    "SwiftSSLSHA256Benchmark_main",
                    "-parse-as-library",
                ]
            )
        else:
            arguments.extend(
                [
                    "-parse-as-library",
                    "-emit-objc-header",
                    "-emit-objc-header-path",
                    str(
                        module_build_root
                        / f"include/{module_name}-Swift.h"
                    ),
                ]
            )
        arguments.extend(["-swift-version", "6"])
        for feature_name in feature_names:
            arguments.extend(
                ["-enable-experimental-feature", feature_name]
            )
        arguments.extend(
            [
                "-I",
                str(testing_library_root),
                "-L",
                str(testing_library_root),
                "-plugin-path",
                str(testing_plugin_root),
                "-sdk",
                str(sdk_path),
                "-F",
                str(platform_framework_root),
                "-I",
                str(platform_library_root),
                "-L",
                str(platform_library_root),
                "-g",
                "-Xcc",
                "-isysroot",
                "-Xcc",
                str(sdk_path),
                "-Xcc",
                "-F",
                "-Xcc",
                str(platform_framework_root),
                "-Xcc",
                "-fPIC",
                "-Xcc",
                "-g",
                "-package-name",
                "swift_ssl",
            ]
        )
        return "builtin-SwiftDriver -- " + " ".join(arguments)

    @staticmethod
    def create_swift_source_lists(
        swift_source: Path,
        swift_scratch: Path,
    ) -> dict[str, Path]:
        module_directories = {
            "SwiftSSLCore": swift_source / "Sources/SwiftSSLCore",
            "SwiftSSLCrypto": swift_source / "Sources/SwiftSSLCrypto",
            "SwiftSSLSHA256Benchmark": (
                swift_source / "Benchmarks/SHA256/SwiftWorker"
            ),
        }
        response_paths: dict[str, Path] = {}
        for module_name, source_directory in module_directories.items():
            source_directory.mkdir(parents=True)
            source_path = source_directory / f"{module_name}.swift"
            source_path.write_text(
                f"enum {module_name}Fixture {{}}\n",
                encoding="utf-8",
            )
            response_path = (
                swift_scratch
                / "arm64-apple-macosx/release"
                / f"{module_name}.build/sources"
            )
            response_path.parent.mkdir(parents=True)
            response_path.write_text(
                f"{source_path.resolve()}\n",
                encoding="utf-8",
            )
            response_paths[module_name] = response_path
        return response_paths

    @staticmethod
    def boringssl_compile_entry(
        source: str,
        *,
        optimization: str,
        compiler: str | None = None,
    ) -> dict[str, object]:
        source_suffix = Path(source).suffix
        selected_compiler = compiler or (
            "/trusted/clang++"
            if source_suffix in (".cc", ".cpp")
            else "/trusted/clang"
        )
        include_flag = "-I/source/include"
        target_arguments = [
            optimization,
            "-DNDEBUG",
            "-arch",
            runner.EXPECTED_ARCHITECTURE,
            "-isysroot",
            "/trusted/SDK",
            f"-mmacosx-version-min={runner.DEPLOYMENT_TARGET}",
        ]
        output_arguments = [
            "-o",
            f"/build/{Path(source).name}.o",
            "-c",
            source,
        ]
        if source.endswith(
            "/Benchmarks/SHA256/BoringSSLDriver/SHA256Benchmark.cpp"
        ):
            arguments = [
                selected_compiler,
                "--driver-mode=g++",
                include_flag,
                *target_arguments,
                *output_arguments,
            ]
        elif source_suffix == ".S":
            arguments = [
                selected_compiler,
                "-DBORINGSSL_IMPLEMENTATION",
                include_flag,
                "-Wa,--noexecstack",
                *target_arguments,
                *output_arguments,
            ]
        else:
            arguments = [
                selected_compiler,
                "--driver-mode=g++",
                "-DBORINGSSL_IMPLEMENTATION",
                include_flag,
                "-fno-strict-aliasing",
                "-ggdb",
                "-fno-common",
                "-fvisibility=hidden",
                optimization,
                "-DNDEBUG",
                "-std=gnu++17",
                "-arch",
                runner.EXPECTED_ARCHITECTURE,
                "-isysroot",
                "/trusted/SDK",
                f"-mmacosx-version-min={runner.DEPLOYMENT_TARGET}",
                "-Werror",
                "-Wformat=2",
                "-Wmissing-field-initializers",
                "-Wshadow",
                "-Wsign-compare",
                "-Wtype-limits",
                "-Wvla",
                "-Wwrite-strings",
                "-Wimplicit-fallthrough",
                "-Wall",
                "-Wnewline-eof",
                "-Wextra-semi",
                "-fcolor-diagnostics",
                "-Wheader-hygiene",
                "-Wmissing-prototypes",
                "-Wstring-concatenation",
                "-Wframe-larger-than=25344",
                "-Wctad-maybe-unsupported",
                "-fno-exceptions",
                "-fno-rtti",
                *output_arguments,
            ]
        return {
            "file": source,
            "directory": "/build",
            "arguments": arguments,
        }

    @classmethod
    def valid_boringssl_compile_database(cls) -> list[dict[str, object]]:
        return [
            cls.boringssl_compile_entry(
                (
                    "/source/Benchmarks/SHA256/BoringSSLDriver/"
                    "SHA256Benchmark.cpp"
                ),
                optimization="-O3",
            ),
            cls.boringssl_compile_entry(
                "/source/crypto/cpu_aarch64_apple.cc",
                optimization="-O3",
            ),
            cls.boringssl_compile_entry(
                "/source/crypto/fipsmodule/bcm.cc",
                optimization="-O3",
            ),
            cls.boringssl_compile_entry(
                "/source/crypto/sha/sha256.cc",
                optimization="-O3",
            ),
            cls.boringssl_compile_entry(
                "/source/gen/bcm/sha256-armv8-apple.S",
                optimization="-O3",
            ),
        ]

    @staticmethod
    def boringssl_toolchain() -> dict[str, object]:
        return {
            "clangCompiler": "/trusted/clang",
            "clangxxCompiler": "/trusted/clang++",
            "ninja": {"path": "/trusted/ninja"},
            "macOSSDKPath": "/trusted/SDK",
        }

    @staticmethod
    def boringssl_cmake_cache() -> str:
        values = {
            "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_ASM_FLAGS_RELEASE": "-O3 -DNDEBUG",
            "CMAKE_CXX_FLAGS_RELEASE": "-O3 -DNDEBUG",
            "CMAKE_C_FLAGS_RELEASE": "-O3 -DNDEBUG",
            "CMAKE_ASM_COMPILER": "/trusted/clang",
            "CMAKE_C_COMPILER": "/trusted/clang",
            "CMAKE_CXX_COMPILER": "/trusted/clang++",
            "CMAKE_CXX_COMPILER_ARG1": "--driver-mode=g++",
            "CMAKE_MAKE_PROGRAM": "/trusted/ninja",
            "CMAKE_OSX_ARCHITECTURES": runner.EXPECTED_ARCHITECTURE,
            "CMAKE_OSX_DEPLOYMENT_TARGET": runner.DEPLOYMENT_TARGET,
            "CMAKE_OSX_SYSROOT": "/trusted/SDK",
            "CFI": "OFF",
            "MSAN": "OFF",
            "OPENSSL_NO_ASM": "OFF",
        }
        return "\n".join(f"{key}:STRING={value}" for key, value in values.items())

    @staticmethod
    def create_dependency_fixture(root: Path) -> dict[str, object]:
        build = root / "build"
        object_path = build / "CMakeFiles/crypto.dir/sha256.cc.o"
        object_path.parent.mkdir(parents=True)
        object_path.write_bytes(b"object")

        boringssl_source = root / "boringssl"
        boringssl_header = boringssl_source / "include/openssl/sha.h"
        boringssl_header.parent.mkdir(parents=True)
        boringssl_header.write_text("boringssl", encoding="utf-8")

        driver_source = (
            root
            / "swift/Benchmarks/SHA256/BoringSSLDriver/SHA256Benchmark.cpp"
        )
        driver_source.parent.mkdir(parents=True)
        driver_source.write_text("driver", encoding="utf-8")

        sdk_root = root / "SDK"
        sdk_header = sdk_root / "usr/include/stdint.h"
        sdk_header.parent.mkdir(parents=True)
        sdk_header.write_text("sdk", encoding="utf-8")

        clang_resource = root / "toolchain/usr/lib/clang/21"
        clang_header = clang_resource / "include/stddef.h"
        clang_header.parent.mkdir(parents=True)
        clang_header.write_text("clang", encoding="utf-8")

        dependencies = (
            boringssl_header,
            driver_source,
            sdk_header,
            clang_header,
        )
        stdout = (
            "CMakeFiles/crypto.dir/sha256.cc.o: #deps 4, "
            "deps mtime 1 (VALID)\n"
            + "".join(
                f"    {dependency}\n" for dependency in dependencies
            )
        )
        return {
            "build": build,
            "boringssl_source": boringssl_source,
            "driver_source": driver_source,
            "sdk_root": sdk_root,
            "sdk_header": sdk_header,
            "clang_resource": clang_resource,
            "compile_outputs": [
                {
                    "source": str(boringssl_header),
                    "object": str(object_path),
                }
            ],
            "required_outputs": {"sha256": str(object_path)},
            "completed": subprocess.CompletedProcess(
                args=["ninja", "-t", "deps"],
                returncode=0,
                stdout=stdout,
                stderr="",
            ),
        }

    @staticmethod
    def synthetic_kernel(
        *,
        extra_loop_instruction: str,
    ) -> dict[str, object]:
        instructions: list[tuple[int, str, str]] = []
        address = 0x80
        for register in range(2, 18):
            instruction = f"ldr q{register}, [x9]"
            instructions.append((address, instruction, instruction))
            address += 4

        loop_start = 0x100
        loop_instructions = [
            "ldp q20, q21, [x0]",
            "ldp q22, q23, [x0, #0x20]",
            extra_loop_instruction,
        ]
        loop_instructions.extend("sha256h.4s q0, q1, v2" for _ in range(16))
        loop_instructions.extend("sha256h2.4s q1, q0, v2" for _ in range(16))
        address = loop_start
        for instruction in loop_instructions:
            instructions.append((address, instruction, instruction))
            address += 4
        instructions.append(
            (
                address,
                f"b.hi 0x{loop_start:x}",
                f"b.hi 0x{loop_start:x}",
            )
        )
        return {
            "symbol": "synthetic multi-block kernel",
            "functionStart": 0x40,
            "functionEnd": address + 4,
            "instructions": instructions,
        }

    @staticmethod
    def synthetic_context_update() -> dict[str, object]:
        call_instructions = [
            "bl CryptoInputErrorOACs0E0AAWl",
            "bl swift_willThrowTypedImpl",
            "bl _memmove",
            "bl _memmove",
            "bl compressMultipleBlocks",
            "stp q0, q1, [x20]",
            "bl stack_chk_fail",
        ]
        return {
            "symbol": "synthetic SHA256Context.update",
            "functionStart": 0x500,
            "functionEnd": 0x600,
            "instructions": [
                (0x500 + index * 4, instruction, instruction)
                for index, instruction in enumerate(call_instructions)
            ],
        }

    @staticmethod
    def synthetic_finalize() -> dict[str, object]:
        call_instructions = [
            "bl _bzero",
            "bl _bzero",
            "bl CryptoInputErrorOACs0E0AAWl",
            "bl swift_willThrowTypedImpl",
            "bl stack_chk_fail",
        ]
        return {
            "symbol": "synthetic SHA256Context.finalizeInPlace",
            "functionStart": 0x700,
            "functionEnd": 0x800,
            "instructions": [
                (0x700 + index * 4, instruction, instruction)
                for index, instruction in enumerate(call_instructions)
            ],
        }


if __name__ == "__main__":
    unittest.main()
