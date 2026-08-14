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
`SHA256H`/`SHA256H2` pair, preserves both old state values when later
same-block users require them, and rewrites those users to the preserved
registers. This lets both destructive state updates remain in place and keeps
their preservation moves outside the `SHA256H`/`SHA256H2` pair. The public
Swift API, input ownership, and WASI/Embedded backends are unchanged.

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

The 2026-08-13 validation built `llc` in Release mode with assertions and the
AArch64 target. The end-to-end IR fixture and the machine-pass MIR fixture both
passed the exact checkout's LLVM 21.1.6 `llc`, machine verifier, and FileCheck.
The MIR fixture covers the positive state/feed-forward rewrite and rejects
mismatched-work and nonadjacent pairs. The macOS arm64 triple produced the same
expected instruction shape. The patched compiler then compiled the production
optimized `SSLCrypto` IR through the standalone benchmark runner. The retained
patch SHA-256 is
`571561f22f755d026f3fa7cfd724170a9d2d17841c66d0bd7ecd92036276d754`;
the IR SHA-256 is
`a6b413cc2251a59f161dd5b2b6b0ba22bd19ec78bc6639b8569e6bfb715414d7`;
and the object SHA-256 is
`7c1c5d0ea6a5507dd9c7ff928d964e04fa9dff123571433866d658d07d747ca0`.
The resulting executable matched pinned BoringSSL for all 768 differential
digests: 256 mutations at each of 64 B, 1 KiB, and 16 KiB.

The patched production kernel keeps all 16 `SHA256H`/`SHA256H2` pairs adjacent.
In 30 balanced exploratory pairs against pinned BoringSSL, it measured
`1.207458x` at 64 B, `1.015725x` at 1 KiB, and `1.000372x` at 16 KiB. The
corresponding 95% paired bootstrap lower bounds were `1.205406x`, `1.012672x`,
and `1.000084x`. Thus both block-dominated workloads pass the explicit `1.0x`
Native one-shot parity floor. They do not satisfy the separate `1.10x` target.
The result is exploratory because the runner used the dirty live Swift tree
and a prebuilt external `llc`; neither condition is accepted for formal release
evidence.

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
