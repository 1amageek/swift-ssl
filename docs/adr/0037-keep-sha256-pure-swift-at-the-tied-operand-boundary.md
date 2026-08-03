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

## 2026-08-03 low-level follow-up

The scalar path adopted the independently measured low-level structure from
the Pure Swift WASM implementation in `1amageek/swift-crypto`: complete blocks
remain borrowed, initial words use scoped unaligned `UInt32` loads, and a
block-aligned message uses a directly constructed padding schedule. These
changes remove avoidable scalar byte assembly and known-padding
materialization without changing the public API or weakening ownership.

This is compatible with the decision above. It improves a distinct scalar and
finalization boundary; it does not remove the tied-operand copy in the Native
ARM64 multi-block kernel. Native boundary and scalar/ARM64 differential tests,
focused Address Sanitizer execution, and Release WASI and Embedded WASI target
validation passed.

A target-specific paired exploratory run then compared the public one-shot
path with official BoringSSL commit
`ae49d2681a56ca7b8609f6039a770fda2a8eb550`, built as a portable no-assembly
WASI baseline. Ordinary and Embedded WASI each measured aligned 1 MiB, aligned
1 MiB + 1 byte, and unaligned 1 MiB + 1 byte workloads. Median speedups ranged
from `1.3311x` to `1.3389x`; every paired 95% bootstrap confidence-interval
lower bound was at least `1.3258x`, so all six workloads passed the `1.10x`
criterion. Thirteen boundary and unaligned validation cases matched both
BoringSSL and Python `hashlib` before timing.

The WASI artifact remains exploratory because the Swift tree was dirty and the
run used 11 pairs rather than the 30-pair formal minimum. A formal Native timing
rerun was not accepted because unrelated active builds prevented the
host-quiescence precondition. Therefore the prior formal Native ratios remain
authoritative; the portable WASI result does not imply parity with BoringSSL's
Native assembly backend.

A separate exploratory WasmKit memory run isolated the production hashing loop
after input/output owner construction. For ordinary and Embedded WASI, aligned
1 MiB, aligned 1 MiB + 1 byte, and unaligned 1 MiB + 1 byte all performed zero
heap allocation calls, zero dynamic copy-function calls, and zero fixed-size
Swift copy-helper bytes per operation. Counters were derived from deterministic
linear profiles at 1, 10, and 100 operations with three repetitions. The
1 MiB + 1-byte paths retained only the one algorithm-required tail byte.

WASM code-generation inspection found two `memory.copy` sites in update and
none in finalization on both targets. The production ownership contract bounds
both destinations to the inline 64-byte pending owner, so complete input blocks
remain borrowed and the tested paths perform zero full-input materializations.
This is combined profile, code-generation, and source-contract evidence:
WasmKit does not report individual `memory.copy` executions.

## 2026-08-03 Native dependency-chain follow-up

An Instruments CPU Counters diagnostic run separated front-end delivery from
back-end processing on the fixed 16 KiB workload. The Swift worker reported a
`0.895269` processing bottleneck and `0.283942` execution-latency component;
the pinned BoringSSL worker reported `0.852682` and `0.155256`, respectively.
Critical L1 data-cache-miss components were `0.000006` and `0.000005`. These
counter samples are diagnostic rather than formal timing evidence, but they
reject cache misses and instruction delivery as the primary explanation.

A two-block Pure Swift experiment prepared the next block's message schedule
while hashing the current block. The optimizer removed the fixed 256-byte
scratch completely and emitted a call-free register-only two-block loop.
Differential validation matched BoringSSL for 256 inputs at 64 B, 1 KiB, and
16 KiB. Twelve balanced screening pairs measured only `1.011593x` at 1 KiB and
`1.011914x` at 16 KiB relative to the retained Swift implementation. The
Apple-M4 `llvm-mca` model still reported `130.045` cycles per Swift block,
compared with `114.08` cycles for the pinned BoringSSL hardware loop. The
448-line experiment was therefore reverted: it did not change the recurrent
state dependency and its small gain did not justify the maintenance cost.

Additional minimal probes found no package-level Pure Swift mechanism for
changing that dependency:

- direct ownership spelling with `copy` and `consume` compiled to the original
  function; the compiler explicitly diagnosed `consume` on the bitwise-copyable
  SIMD value as having no effect;
- the Swift compiler's `freeze` builtin is available only while building the
  standard library and cannot be imported by a normal package target;
- the compiler builtin database exposes neither volatile load/store nor inline
  assembly to normal Swift package source;
- separating or parallelizing message-schedule generation leaves the same
  sequential state chain and therefore cannot close the measured gap.

The fixed July 23 Swift 6.4 snapshot consequently has no supported Pure Swift
source construct that expresses BoringSSL's destructive register lifetime.
A Swift/LLVM code-generation change or a future public intrinsic with an
in-place/tied ownership contract is required to recover parity.

That compiler change is not sufficient for the `1.10x` single-stream target.
An Apple-M4 `llvm-mca` lower-bound model removed all input, schedule,
feed-forward, and output instructions while retaining the 16 required
`mov`/`sha256h`/`sha256h2` state pairs. It measured `112.04` cycles per block;
the complete pinned BoringSSL loop measured `114.08`, for a maximum modeled
ratio of `1.0182x`. Hoisting all 16 round constants from the BoringSSL loop
measured `114.09` cycles and therefore supplied no hidden latency reduction.

A temporary diagnostic assembly kernel then tested the same state-only chain
on the actual M4 Max. It preloaded all 16 work vectors and omitted every other
operation required by a correct digest. Eight balanced same-window pairs
produced these medians:

| Headline block count | BoringSSL ns/block | State-only ns/block | Maximum ratio |
|---:|---:|---:|---:|
| 1 KiB (`17` blocks) | `22.663299` | `22.003050` | `1.030007x` |
| 16 KiB (`257` blocks) | `22.833215` | `21.972605` | `1.039167x` |

The lower bound is already short of `1.10x` before restoring message schedule,
input, feed-forward, output, and API costs. Standard SHA-256 also requires the
chaining state of block `i - 1` before block `i`, so the fixed one-shot
single-stream workload cannot use independent-message parallelism without
changing the operation being compared. The `1.10x` Native condition is
therefore infeasible on this pinned CPU/ISA boundary. Assembly, C shims,
workload caching, batched replacement workloads, and a weakened BoringSSL
comparison remain outside this project's Pure Swift benchmark contract.

## 2026-08-03 LLVM backend implementation

The accepted compiler route was implemented against LLVM commit
`264fd65923c28d9060211c1177a8820b76ed3ae2`, the revision embedded in the
pinned Swift snapshot. The AArch64 machine peephole pass now recognizes an
adjacent `SHA256Hrrr`/`SHA256H2rrr` pair with matching state and work operands.
It preserves the old first state using `ORRv16i8`, rewrites later same-block
uses to that preserved register, and thereby lets two-address lowering update
the first hash state in place. A generic `COPY` cannot implement this
transformation because register coalescing recreates the original destructive
destination schedule.

The exact compiler change and its LLVM code-generation test are retained at
`Validation/CodeGeneration/SHA256TiedOperands/llvm-264fd65923c28-sha256-paired-two-address.patch`.
A Release-with-assertions AArch64-only `llc` build passed the exact checkout's
machine verifier and FileCheck for an end-to-end IR fixture and a machine-pass
MIR fixture. The latter covers the positive feed-forward rewrite and rejects
mismatched-work and nonadjacent pairs. The macOS arm64 triple produced the same
expected shape. Compiling the complete optimized production `SwiftSSLCrypto`
IR produced the intended in-place shape for all 16 hash pairs. The final object
was byte-identical to the measured object, with SHA-256
`e1e414aac6f597f28ced2874b6e44d4cd59b34ed7aea9c1367a02aebdf753eeb`.
The linked benchmark executable matched the original Swift executable and
BoringSSL for 768 digests across 64 B, 1 KiB, 16 KiB, and input offsets 0, 1,
7, and 15.

Exploratory paired measurements separated the compiler gain from the remaining
ISA-bound gap:

| Workload | Patched backend / retained Swift | Patched backend / BoringSSL | BoringSSL 95% paired bootstrap CI |
|---|---:|---:|---:|
| 64 B | `1.016362x` | `1.170837x` | `1.166957–1.175070x` |
| 1 KiB | `1.169649x` | `1.014471x` | `1.009768–1.017313x` |
| 16 KiB | `1.190179x` | `1.009975x` | `1.006648–1.013006x` |

The retained-Swift comparison used 16 balanced pairs; the BoringSSL comparison
used 30 balanced pairs and 10,000 paired bootstrap resamples. Both used the
same benchmark worker, inputs, output validation, host, and arm64 target. These
are diagnostic results from a dirty Swift source tree and a separately linked
compiler experiment, so they are not formal release evidence.

The compiler implementation recovers approximately 17–19% on block-dominated
inputs and brings the Pure Swift source to parity with BoringSSL's assembly. It
does not create another 10% of physically available single-stream throughput:
the 1 KiB and 16 KiB confidence intervals remain near `1.01x`, consistent with
the measured state-only maximum of `1.03–1.04x`. The patch therefore resolves
the identified compiler defect without resolving the contradictory Native
release criterion. It is not part of the installed pinned Swift toolchain.

The aggregate state-only results, patched-production intervals, exact toolchain
identities, omitted-work contract, and a standalone arithmetic verifier are
retained as `native-single-stream-ceiling.json` and
`verify-native-single-stream-ceiling.py` beside the LLVM patch. Recalculation
shows that `1.10x` would require per-block state-chain times `6.795374%` below
the measured 1 KiB state-only chain and `5.853974%` below the measured 16 KiB
state-only chain. The original eight raw state-only pairs were not retained;
the certificate records that limitation and remains diagnostic rather than
formal timing evidence.

LLVM 22 `llvm-mca -mcpu=apple-m4` modeled the final patched 101-instruction
production loop at 11,511 cycles over 100 iterations, or `115.11` cycles per
block. The state-only model is `112.04`, so removing all remaining modeled
input, schedule, feed-forward, output, and loop work can recover only `3.07`
cycles before reaching the lower bound that already fails `1.10x`.

## Consequences

- SHA-256 correctness, memory safety, and the zero-copy input path remain
  intact.
- The portable WASI exploratory comparison meets the `1.10x` throughput goal
  for its six measured workloads.
- The exploratory ordinary and Embedded WASI memory evidence meets the
  zero-allocation and zero-full-input-materialization budget for all six
  measured workloads.
- The formal performance release gate remains failed because Native assembly,
  formal WASI evidence, and formal allocation/copy evidence are separate gates;
  this ADR does not waive or redefine them.
- The fixed Native `1.10x` single-stream gate has a measured lower-bound
  contradiction and cannot become a release requirement without changing the
  CPU/ISA boundary or the equivalently compared operation.
- A tested LLVM backend patch removes the tied-operand dependency and recovers
  the expected throughput, but the patched 1 KiB and 16 KiB workloads remain
  approximately `1.01x` BoringSSL rather than `1.10x`.
- Further blind source rearrangement is not part of the optimization loop
  unless it supplies a new register-allocation mechanism or measurement-backed
  hypothesis.
- Other BoringSSL replacement responsibilities can proceed while the compiler
  boundary remains visible in the completion ledger.
