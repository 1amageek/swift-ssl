# ADR 0037: Keep SHA-256 Pure Swift at the tied-operand boundary

## Status

Accepted on 2026-08-01.

## Context

The formal SHA-256 benchmark failed the `1.10x` BoringSSL release goal for all
three fixed workloads. The 1 KiB and 16 KiB results are dominated by the ARM64
multi-block compression loop rather than allocation, input copying, or public
API dispatch.

The production Swift loop emits all 16 `sha256h` and 16 `sha256h2`
instructions required by one block, hoists its 16 constant vectors outside the
block loop, performs two paired input loads, and performs no calls or heap
operations in the loop. Its block body has 100 instructions. The pinned
BoringSSL ARMv8 loop has 115 instructions because it streams round constants,
but its hand-written register schedule avoids a recurrent tied-operand copy.

LLVM defines `SHA256Hrrr` and `SHA256H2rrr` with the constraint
`$Rd = $dst`. The intrinsic is a three-input value operation, so the register
allocator must choose where to preserve the old state needed by the other hash
instruction. Swift and Clang produce the same minimal intrinsic sequence: they
copy a live state into a new destructive result register. BoringSSL assembly
copies the old first state to a temporary and overwrites both state registers
directly.

On the pinned Apple M4 Max environment, `llvm-mca -mcpu=apple-m4` estimates
approximately 130 cycles per Swift block-loop iteration and 114 cycles for the
BoringSSL hardware loop. This is consistent with the formal 16 KiB ratio of
`0.839864x`. The source-level alternatives tested were:

- reversing the `sha256h` and `sha256h2` source order;
- tuple and helper-function arrangements;
- alternate LLVM scheduler and register-allocation controls;
- scalar or volatile constant streaming;
- explicit identity copies;
- an opaque identity `tbl` operation that obtains the desired destructive
  register arrangement.

Only the `tbl` form obtained the desired arrangement. Its real instruction
latency removed the benefit, and five alternating 16 KiB screening pairs did
not show a repeatable improvement. The experiment was reverted.

Primary LLVM definitions:

- `llvm/lib/Target/AArch64/AArch64InstrFormats.td`, `SHA3OpTiedInst` and
  `SHATiedInstQQV`;
- `llvm/lib/Target/AArch64/AArch64InstrInfo.td`, `SHA256Hrrr` and
  `SHA256H2rrr`;
- `llvm/include/llvm/IR/IntrinsicsAArch64.td`,
  `Crypto_SHA_8Hash4Schedule_Intrinsic`.

The source inspected for this decision was llvm-project commit
`b94b699857a5de41b0def1cffca6908e584be27f`.

## Decision

Keep the production kernel in Pure Swift and keep the `1.10x` result recorded
as unmet. Do not add assembly, a C shim, executable-memory code generation,
Apple-only framework dispatch, unsafe package-wide LLVM flags, workload
caching, or a changed comparison operation to claim success.

Maintain a manual code-generation probe under
`Validation/CodeGeneration/SHA256TiedOperands`. Reevaluate the kernel whenever
the pinned Swift/LLVM toolchain changes or the probe no longer observes the
tied-copy shape. A compiler fix or a safe public Swift intrinsic that expresses
the destructive operand lifetime is the accepted route to another formal
benchmark attempt.

## Consequences

- SHA-256 correctness, memory safety, and the zero-copy input path remain
  intact.
- The formal performance release gate remains failed; this ADR does not waive
  or redefine it.
- Further blind source rearrangement is not part of the optimization loop
  unless it supplies a new register-allocation mechanism or measurement-backed
  hypothesis.
- Other BoringSSL replacement responsibilities can proceed while the compiler
  boundary remains visible in the completion ledger.
