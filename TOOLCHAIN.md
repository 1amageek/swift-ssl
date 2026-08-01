# Toolchain contract

`swift-ssl` uses one pinned compiler and matching Swift SDK set for Native, WASI, and Embedded WASI validation. A successful host build does not establish target support.

## Baseline

| Component | Identifier |
|---|---|
| Swift snapshot | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a` |
| macOS toolchain | `org.swift.64202607231a` |
| Swift compiler commit | `ef761e567dc94ee` |
| WASI Swift SDK | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm` |
| Embedded WASI Swift SDK | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded` |

## Build and execution checks

Native correctness tests use Xcode with a bounded external timeout. Cross-target checks compile, link, and execute dedicated validation programs with the exact SDK identifier. Release cross-compilation can exceed the 120-second execution timeout. In that case, build the product first, then run the already-linked product under the bounded wrapper with `--skip-build`; a compile timeout is never reported as a runtime failure.

```sh
TOOLCHAINS=org.swift.64202607231a xcrun swift --version
TOOLCHAINS=org.swift.64202607231a xcrun swift sdk list

scripts/swift-test-timeout.sh 120 \
  env TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test \
  -scheme swift-ssl-Package \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath .build/xcode-derived-data \
  -jobs 2 \
  CODE_SIGNING_ALLOWED=NO

scripts/swift-test-timeout.sh 120 \
  env TOOLCHAINS=org.swift.64202607231a \
  swift run \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  --scratch-path .build/target-validation-wasi \
  swift-ssl-target-validation

scripts/swift-test-timeout.sh 120 \
  env TOOLCHAINS=org.swift.64202607231a \
  swift run \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  --scratch-path .build/target-validation-wasi-embedded \
  swift-ssl-target-validation

swift build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  --product swift-ssl-facade-validation

scripts/swift-test-timeout.sh 120 \
  swift run --skip-build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  swift-ssl-facade-validation

swift build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  --product swift-ssl-quic-crypto-stream-validation

scripts/swift-test-timeout.sh 120 \
  swift run --skip-build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  swift-ssl-quic-crypto-stream-validation
```

The long-running NIST verification program is separate from normal tests and
selects one bounded success or mutation case at manifest-evaluation time:

```sh
SWIFT_SSL_NIST_VALIDATION_CASE=p384-valid \
  swift build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  --product swift-ssl-nist-verification-validation

SWIFT_SSL_NIST_VALIDATION_CASE=p384-valid \
  scripts/swift-test-timeout.sh 120 \
  swift run --skip-build -c release \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  swift-ssl-nist-verification-validation
```

The CI wrapper is responsible for enforcing the timeout and recording the toolchain, SDK, target triple, compiler commit, and linked Embedded platform implementation in each log.

## Target invariants

- Shared mutable state uses the same `Synchronization.Mutex<State>` or actor contract on every target.
- `hasFeature(Embedded)` is never interpreted as a single-threaded guarantee.
- Platform branches may select concrete entropy, clock, persistence, and runtime hooks, but may not change protocol semantics, ownership, or `Sendable` contracts.
- The public API does not require Foundation, Objective-C interoperability, reflection, weak references, sockets, or file I/O.
- A target is supported only after compile, link, and target execution checks. Compile-only evidence is identified as such.
