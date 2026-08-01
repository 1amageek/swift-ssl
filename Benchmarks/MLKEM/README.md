# ML-KEM comparison benchmark

This manually invoked Native benchmark compares the public ML-KEM-768 and
ML-KEM-1024 key-generation, encapsulation, and decapsulation paths with the
same operations in pinned official BoringSSL commit
`ae49d2681a56ca7b8609f6039a770fda2a8eb550`.

The benchmark is enabled only when `SWIFT_SSL_ENABLE_BENCHMARKS=1`. It is not a
test target, is not run by `xcodebuild test`, and does not add BoringSSL to a
SwiftSSL library or runtime target.

```mermaid
flowchart LR
    Runner["Manual paired runner"] --> Swift["SwiftSSL public façade"]
    Runner --> BoringSSL["BoringSSL public ML-KEM API"]
    Swift --> Result["elapsed time + checksum"]
    BoringSSL --> Result
```

Each timed worker performs one public operation per iteration. Key setup for
encapsulation and key/ciphertext setup for decapsulation are outside the timed
region. Public random generation remains inside key generation and
encapsulation for both implementations. The checksum consumes public output
and shared-secret bytes so the operation cannot be removed.

Formal release evidence additionally requires runner-owned clean source
snapshots, pinned build provenance, paired sampling, confidence intervals,
worker code-generation inspection, and correctness/interoperability validation.

## Formal runner

The runner owns both fresh builds and accepts source trees rather than worker
paths. A formal run requires the pinned toolchain in the process environment
and a clean committed SwiftSSL checkout:

```bash
TOOLCHAINS=org.swift.64202607231a \
python3 Benchmarks/MLKEM/run_comparison.py \
  --formal \
  --boringssl-source /absolute/path/to/pinned/boringssl \
  --samples 30 \
  --bootstrap-resamples 10000 \
  --seed 20260801
```

The command is manual. `Package.swift` adds the Swift worker only while
`SWIFT_SSL_ENABLE_BENCHMARKS=1`; normal products and test runs do not compile
or link either benchmark worker.

```mermaid
flowchart LR
    Commits["clean pinned commits"] --> Snapshots["read-only git archives"]
    Snapshots --> Builds["fresh arm64 Release builds"]
    Builds --> Interop["bidirectional interoperability"]
    Interop --> Codegen["Mach-O and code-generation gates"]
    Codegen --> Converge["duration calibration and convergence"]
    Converge --> Pairs["30 balanced randomized pairs"]
    Pairs --> Artifact["atomic raw JSON artifact"]
```

The pre-timing interoperability transaction uses deterministic 64-byte key
seeds for both parameter sets. SwiftSSL-generated public keys, ciphertexts,
and shared secrets are validated by BoringSSL. A separately generated
BoringSSL ciphertext is validated and decapsulated by SwiftSSL. A mutated
ciphertext must produce the same implicit-rejection secret in both
implementations and must not reproduce the valid shared secret.

The build gate fixes arm64, macOS 15.0, SDK 27.0, Xcode 27 build `27A5209h`,
and Swift compiler commit `ef761e567dc94ee`. It rejects non-Release,
sanitizer, profiling, coverage, or BoringSSL assembly-disable flags. Both
workers must have matching Mach-O architecture, platform, minimum OS, and SDK
load commands. The Swift code-generation gate requires the specialized NTT
SIMD reduction shape and ARM SHA3 instructions. The BoringSSL worker must
contain both ML-KEM parameter-set entry points and confirm assembly capability
at runtime.

Each implementation must exceed 200 ms per calibrated sample with the same
iteration count. The latest three pilot durations for each implementation must
remain within five percent of their median. Timing begins only while the host
is on AC power, normal power mode, without thermal or performance warnings,
without a compiler/linker build process, and below the declared load ceiling.
The runner repeats this check before every convergence and measured pair.

The release decision is made independently for all six workloads:

```text
lower95CI(median(BoringSSL elapsed / SwiftSSL elapsed)) >= 1.10
```

Timing evidence does not establish allocation or logical-copy counts. Those
remain a separate instrumented release artifact even though this worker uses
the public in-place encapsulation and decapsulation APIs.

## Allocation and bulk-copy runner

The memory runner is also manual and separate from the test targets. It builds
a fresh Release worker from a clean Git archive, injects a benchmark-only
allocator/copy interposer, validates that interposer with a C contract probe,
and measures the public entropy-injected operation at 1, 10, and 100
iterations in three fresh processes each.

```bash
TOOLCHAINS=org.swift.64202607231a \
python3 Benchmarks/MLKEM/run_memory.py --formal
```

For each counter, the runner requires an exact linear relation between the
three iteration counts. The slope is the per-operation count and the intercept
is process/setup overhead. In-place encapsulation and decapsulation must not
perform a general `malloc`, and allocation/free slopes must balance. Dynamic
`memcpy`/`memmove` bytes must have a zero per-operation slope. The declared
allocation budgets include algorithm workspaces and owned key results; they do
not assert that ML-KEM is allocation-free.

macOS aliases the public `memcpy` and `memmove` implementations, so their two
individual call counters are diagnostic only; the gate uses their combined
byte slope. The interposer cannot see compiler-inlined scalar assignments.
Consequently, the artifact is combined with the safe API contract and source
review: caller inputs stay borrowed, serialized outputs are written directly
into caller-owned spans, and algorithm-required result writes are not described
as avoided copies.

## Formal result

The 2026-08-01 run used SwiftSSL commit
`a96fee3d2e688fa331ff50a2582c7a97f9886f65` and passed every workload gate.

| Workload | Swift median ns/op | BoringSSL median ns/op | Paired speedup | 95% bootstrap CI |
|---|---:|---:|---:|---:|
| ML-KEM-768 key generation | 9,774.244 | 12,254.085 | 1.2540x | 1.2490–1.2557 |
| ML-KEM-768 encapsulation | 4,486.583 | 5,635.634 | 1.2545x | 1.2521–1.2579 |
| ML-KEM-768 decapsulation | 7,777.706 | 8,658.050 | 1.1128x | 1.1089–1.1150 |
| ML-KEM-1024 key generation | 14,216.063 | 19,141.245 | 1.3450x | 1.3426–1.3470 |
| ML-KEM-1024 encapsulation | 5,772.702 | 7,561.406 | 1.3109x | 1.3074–1.3135 |
| ML-KEM-1024 decapsulation | 10,429.674 | 11,746.667 | 1.1267x | 1.1248–1.1305 |

The raw artifact is
[`Results/20260801T115837Z-native-mlkem.json`](Results/20260801T115837Z-native-mlkem.json)
with SHA-256
`7c6b21acdb079a55779d64b21cdf03accac1d8df75c18d67b3383f41cba83ec8`.
It records the clean source commits and archives, tool and worker hashes,
compile contracts, code-generation gates, interoperability transaction,
quiescence observations, calibration, convergence, all 30 samples, and the
10,000-resample paired confidence intervals.

### Formal memory result

The 2026-08-01 memory run used SwiftSSL commit
`2cfb10d9969c9ca24592b6de86649ebf9b19331c` and passed all six declared
allocation and dynamic-copy budgets.

| Path | Allocation/free calls per operation | Requested bytes | General `malloc` | Dynamic bulk-copy bytes |
|---|---:|---:|---:|---:|
| ML-KEM-768 key generation | 17 / 17 | 20,640 | 6 | 0 |
| ML-KEM-768 in-place encapsulation | 5 / 5 | 6,096 | 0 | 0 |
| ML-KEM-768 in-place decapsulation | 11 / 11 | 9,808 | 0 | 0 |
| ML-KEM-1024 key generation | 17 / 17 | 31,008 | 6 | 0 |
| ML-KEM-1024 in-place encapsulation | 5 / 5 | 7,632 | 0 | 0 |
| ML-KEM-1024 in-place decapsulation | 11 / 11 | 12,336 | 0 | 0 |

The raw artifact is
[`Results/20260801T122012Z-native-mlkem-memory.json`](Results/20260801T122012Z-native-mlkem-memory.json)
with SHA-256
`36658642dc4c2bc791288b55fd089f18ac6772cb4b50c0f1dca057a58ec339c5`.
