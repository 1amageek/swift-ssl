# SHA-256 ARM64 tied-operand code-generation probe

This manual validation captures the compiler boundary behind the ARM64
SHA-256 throughput gap. It is separate from unit tests and benchmarks.

Run it with the pinned Swift toolchain:

```sh
Validation/CodeGeneration/SHA256TiedOperands/capture-current-codegen.sh
```

Both the Swift and Clang intrinsic forms currently lower a four-round pair by
copying a live input into the destructive destination before `sha256h` or
`sha256h2`. BoringSSL's pinned hand-written assembly instead copies the old
state to a temporary, overwrites both state registers directly, and uses the
temporary as the second hash instruction's input.

The script intentionally fails if the copy shape disappears. That outcome is
not a regression: it means the pinned toolchain changed and the production
kernel and formal benchmark must be reevaluated.

## LLVM backend experiment

`llvm-264fd65923c28-sha256-paired-two-address.patch` is a reproducible compiler
patch for LLVM commit `264fd65923c28d9060211c1177a8820b76ed3ae2`, the LLVM
revision embedded in the pinned Swift snapshot. It changes the AArch64 machine
peephole pass, not the SSL product source. The pass recognizes an adjacent
`SHA256H`/`SHA256H2` pair, preserves the old first state with the target vector
move form, and rewrites later same-block users to the preserved register. The
public Swift API, input ownership, and WASI/Embedded backends are unchanged.

Apply and verify it from a matching `swiftlang/llvm-project` checkout:

```sh
git apply /path/to/llvm-264fd65923c28-sha256-paired-two-address.patch
cmake --build /path/to/llvm-build --target llc --parallel 10
/path/to/llvm-build/bin/llc \
  -verify-machineinstrs \
  -mtriple=aarch64-linux-gnu \
  -mattr=+sha2 \
  llvm/test/CodeGen/AArch64/sha256-paired-two-address.ll \
  | /path/to/llvm-build/bin/FileCheck \
      llvm/test/CodeGen/AArch64/sha256-paired-two-address.ll
/path/to/llvm-build/bin/llc \
  -run-pass=aarch64-mi-peephole-opt \
  -verify-machineinstrs \
  -mtriple=aarch64-unknown-linux \
  -o - \
  llvm/test/CodeGen/AArch64/peephole-sha256-paired-two-address.mir \
  | /path/to/llvm-build/bin/FileCheck \
      llvm/test/CodeGen/AArch64/peephole-sha256-paired-two-address.mir
```

The 2026-08-03 validation built `llc` in Release mode with assertions and the
AArch64 target. The end-to-end IR fixture and the machine-pass MIR fixture both
passed the exact checkout's LLVM 21.1.6 `llc`, machine verifier, and FileCheck.
The MIR fixture covers the positive state/feed-forward rewrite and rejects
mismatched-work and nonadjacent pairs. The macOS arm64 triple produced the same
expected instruction shape. The patched compiler then compiled the production
optimized `SSLCrypto` IR. Its object SHA-256 was
`e1e414aac6f597f28ced2874b6e44d4cd59b34ed7aea9c1367a02aebdf753eeb` before
and after the final same-block-use audit, directly binding the recorded timing
binary to the retained patch. The resulting executable matched both the pinned
Swift binary and BoringSSL for 768 digests spanning 64 B, 1 KiB, 16 KiB, and
input offsets 0, 1, 7, and 15.

The patched production kernel keeps `SHA256H` in place for all 16 pairs. In 30
balanced exploratory pairs against pinned BoringSSL, it measured `1.170837x`
at 64 B, `1.014471x` at 1 KiB, and `1.009975x` at 16 KiB. The corresponding
95% paired bootstrap lower bounds were `1.166957x`, `1.009768x`, and
`1.006648x`. This proves that the tied-operand compiler defect can be removed,
but it does not satisfy the project-wide `1.10x` Native gate for the two
block-dominated workloads.

## Native single-stream ceiling certificate

`native-single-stream-ceiling.json` retains the aggregate state-only M4
measurements, the llvm-mca model, the patched-production confidence intervals,
the exact toolchain identities, and the deliberately omitted work. It is
classified as diagnostic impossibility evidence rather than a benchmark pass.
Verify its arithmetic and fixed instruction/omission contract separately from
the normal test suite:

```sh
python3 \
  Validation/CodeGeneration/SHA256TiedOperands/verify-native-single-stream-ceiling.py
```

The verifier recomputes every maximum ratio and the per-block time that a
`1.10x` result would require. The 1 KiB state-only chain is `6.795374%` slower
than that required time, and the 16 KiB chain is `5.853974%` slower, before
restoring any operation required to produce a digest. It also requires the
patched-production confidence-interval upper bounds for both block workloads
to remain below `1.10x`.

The final patched production loop was also passed directly to LLVM 22
`llvm-mca -mcpu=apple-m4` for 100 iterations. Its 101-instruction block used
11,511 modeled cycles (`115.11` per block), compared with `112.04` for the
state-only chain. Removing every modeled non-state instruction can therefore
recover only `3.07` cycles before reaching the already-failing state bound.

This certificate makes the contradiction reproducible from retained aggregate
evidence, but it does not reconstruct the discarded eight raw state-only
pairs. That limitation is encoded in the JSON and prevents promotion to formal
benchmark evidence.
