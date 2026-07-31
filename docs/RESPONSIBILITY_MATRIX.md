# Responsibility matrix

This matrix is the completeness ledger for replacing BoringSSL. Completeness means that no modern responsibility is unowned; it does not mean source or ABI compatibility.

## 1. C-oriented mechanisms and Swift replacements

| BoringSSL mechanism | `swift-ssl` owner | Decision |
|---|---|---|
| `CBS` borrowed parser input | `SwiftSSLCore` span-based cursors | Replace with scoped `Span` and checked ranges |
| `CBB` output construction | `SwiftSSLCore` bounded builder | Replace with one contiguous owner and caller-buffer output where sized |
| `CRYPTO_BUFFER` / pools | `SwiftSSLASN1` and `SwiftSSLX509` immutable DER owners | Replace with owner plus ranges; no process-global pool requirement |
| `EVP` algorithm dispatch | `SwiftSSLCrypto` narrow protocols and closed algorithm identifiers | Replace; no numeric NID or generic control channel |
| `BIO` | Application transport and explicit byte owners | Exclude; protocol engines perform no I/O |
| `SSL_CTX` / mutable callback configuration | Immutable configuration values and capability requests | Replace; no reentrant callback state |
| `ERR` queue | Typed errors and protocol alert/disposition values | Replace; no thread-local queue |
| `ex_data` | Explicit generic application context outside core state | Replace; no untyped indexed slots |
| reference counts and `get0/get1/set0/set1` | Swift ownership, borrowing, consuming, and noncopyable types | Replace; ownership is visible in type signatures |
| thread callbacks and platform locks | `Synchronization.Mutex<State>` or actor | Replace with one cross-target isolation contract |
| public mutable `BIGNUM` | Fixed-width internal limb types per algorithm | No general public mutable big-number API |
| global RAND behavior | Injected `EntropySource` and explicit DRBG owners | Replace; no hidden fallback or abort-only contract |

## 2. Cryptographic responsibility

Status values are `required`, `policy-gated`, `experimental`, `later`, and `excluded`.

| Family | Algorithms/constructions | Status | Owner and notes |
|---|---|---|---|
| Hash | SHA-256, SHA-384, SHA-512 | Required | `SwiftSSLCrypto`; SHA-256/384/512 callable implementations are present; TLS and signature dependencies remain to be integrated |
| SHA-3/XOF | SHA3-256/512, SHAKE128/256 | Required | `SwiftSSLCrypto`; PQ dependencies |
| Additional hash | BLAKE2 variants still justified by modern callers | Later | Separate from TLS completion; no BoringSSL symbol compatibility |
| MAC | HMAC-SHA-256/384/512 | Required | `SwiftSSLCrypto` and façade implementations with constant-time tag verification |
| KDF | HKDF-SHA-256/384/512 | Required | Extract/expand implementations; TLS and HPKE labels remain separate constructions |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | Required | AES-GCM and ChaCha20-Poly1305 callable implementations; all TLS 1.3 cipher suites still require TLS engine integration; open failure exposes no plaintext |
| Classical KEX | X25519, P-256, P-384, P-521 | Required | X25519 is implemented in `SwiftSSLCrypto` and `SwiftSSL`; P-256/P-384/P-521 remain required for a complete signature/key profile |
| Classical signature | Ed25519; ECDSA P-256/384/521; RSA-PSS SHA-256/384/512 | Required | TLS 1.3 authentication and PKI |
| Certificate compatibility verification | RSA PKCS #1 v1.5 with approved SHA-2 hashes | Policy-gated | Verification only for deployed PKI; never a TLS CertificateVerify signer |
| ML-KEM | ML-KEM-768 and ML-KEM-1024 | Required | FIPS 203 semantics; implicit rejection for correctly sized ciphertext |
| ML-DSA | ML-DSA-44/65/87 | Required primitive | FIPS 204; TLS/X.509 use remains wire-policy gated |
| TLS hybrid | X25519MLKEM768 at the pinned current draft revision | Experimental until standardized | Default eligibility requires explicit revision policy; draft Kyber group is excluded |
| HPKE | RFC 9180 Base, PSK, Auth, and AuthPSK modes with X25519/P-256, HKDF, supported AEADs | Required | Intentional RFC-complete surface beyond BoringSSL's public Base/Auth setup API; sender/recipient context types are distinct |
| PQ HPKE/X-Wing | Standardized ML-KEM suites and X-Wing draft profile | Experimental | X-Wing KEM is not the TLS X25519MLKEM concatenation construction |
| SLH-DSA | FIPS 205 parameter sets | Later | Primitive surface; no pretend TLS/X.509 integration |
| Entropy/DRBG | Explicit entropy source and reseed-capable DRBG | Required | `HMACDRBG` implements SP 800-90A-style HMAC-SHA-256 state with injected `EntropySource`; process-fork detection and platform health adapters remain external |
| Constant-time utilities | equality, conditional selection, fixed-width arithmetic helpers | Required | Internal/public boundary carefully limited |

## 3. Formats and PKI responsibility

| Responsibility | Status | Contract |
|---|---|---|
| Strict DER TLV and primitive codecs | Required | Canonical encoding, complete consumption, checked arithmetic, explicit budgets |
| RFC 7468 PEM | Required | Known labels, strict Base64, decoded DER owner; malformed blocks are typed failures |
| BER-to-DER repair | Excluded | No silent compatibility normalization |
| SPKI and PKCS #8 | Required | Algorithm-specific validation and canonical output |
| Encrypted PKCS #8 | Required | Explicit modern encryption profiles and password handling policy |
| PKCS #12 | Required | Certificate/key interchange without reproducing legacy OpenSSL APIs |
| CMS/PKCS #7 certificate containers | Required subset | Parse and emit the certificate-container responsibility needed by current ecosystems |
| X.509 certificate and extension parse | Required | Immutable DER owner plus ranges; syntax validity is not path validity |
| RFC 5280 path building and validation | Required | Bounded search, loop detection, signature/algorithm policy, no partial success |
| Service identity | Required | SAN-only matching; no Common Name fallback |
| Trust store | Required protocol | Caller-supplied immutable trust records; platform adapters are separate |
| CRL and OCSP | Required | Acquisition, evidence validation, and hard/soft-fail policy separated |
| Certificate Transparency inputs | Required | SCT parsing and verification capability; log-list acquisition is external |
| Delegated credentials | Required | TLS policy-gated modern extension |
| Raw public keys | Required | Explicit authentication profile, never confused with X.509 trust |
| Certificate compression | Required | Bounded decompression and transcript-correct encoding |

## 4. Secure transport responsibility

| Responsibility | Status | Boundary |
|---|---|---|
| TLS 1.3 stream | Required | Handshake, record layer, key schedule, alerts, client auth, post-handshake tickets/key update |
| TLS resumption | Required | Immutable, identity-bound, expiring, single-use policy-capable state |
| TLS 0-RTT | Required | Separate from resumption; explicit replay policy; no automatic replay |
| ECH RFC 9849 | Required | HPKE inner/outer and retry outcome; DNS and retry transport external |
| DTLS 1.3 | Required | Epoch/sequence/replay, fragmentation, ACK, flight and timer state, CID |
| DTLS-SRTP | Required | Negotiation/exporter boundary; media transport external |
| QUIC RFC 9001 | Required | TLS handshake bytes and secret events only |
| ALPN, SNI, record size limit | Required | Typed extension configuration and negotiated results |
| Key logging | Debug-only policy | Explicit diagnostic capability, unavailable by default, secrets never reach general logs |
| SSL/TLS 1.0-1.2 | Excluded | No downgrade or compatibility backend |
| DTLS 1.0-1.2 | Excluded | No old record/handshake profile |
| Renegotiation, False Start, NPN, Channel ID | Excluded | Historical features outside the modern profile |

## 5. Explicit legacy algorithm exclusions

The implementation does not contain negotiation or compatibility paths for MD4, MD5, MD5-SHA1, RC4, DES, 3DES, Blowfish, CAST, TLS CBC suites, RSA key transport, finite-field DH, DSA, ECDSA-SHA1, RSA PKCS #1 v1.5 TLS handshake signing, or `X25519Kyber768Draft00`.

Unknown, excluded, and experimental-disabled algorithms remain distinguishable typed policy failures.

## 6. Draft and standards policy

- Final standards receive stable public identifiers.
- Draft algorithms live in an explicitly experimental namespace that includes a revision.
- Draft wire identifiers are not silently reinterpreted after an update.
- A draft update requires vector refresh, interoperability evidence, migration notes, and an explicit decision record.
- FIPS algorithm conformance does not imply that this library is a FIPS-validated module.

## 7. Completion ledger

The implementation status is tracked by responsibility rather than by header count. A row changes to complete only after the gates in `VERIFICATION.md` pass. Missing APIs remain documentation backlog until a callable implementation exists; callable partial paths must fail explicitly and carry the required incomplete-implementation marker.

### 7.1 Current implementation snapshot

No row below is complete unless the evidence column explicitly says that every completion gate passed.

| Responsibility | Production implementation now | Evidence now | Remaining before complete |
|---|---|---|---|
| Core byte and secret foundation | Owned contiguous bytes, scoped spans, checked cursor/builder/ranges, parsing budgets, noncopyable secret allocation and wipe | Native unit tests, lifetime-negative fixtures, Native/WASI/Embedded WASI target-validation execution, ASan/TSan/UBSan, optimized wipe inspection | Measured copy/allocation budgets and archived release-gate logs |
| SHA-256 | Real incremental and one-shot implementation with scalar and ARM64 kernels and caller-provided output | Known-answer/boundary tests, million-byte vector, scalar/ARM64 comparison, Native/WASI/Embedded WASI target-validation execution, sanitizer coverage | Committed independent differential evidence and formal clean benchmark |
| HMAC-SHA-256 | Real incremental and one-shot keyed implementation with noncopyable context, stable secret-state storage, caller-provided output, and constant-time verification | RFC 4231 cases 1/2/3/4/6/7, incremental and failure-contract tests, Native/WASI/Embedded WASI façade execution, ASan/TSan/UBSan, `-O`/`-Osize` in-place wipe inspection | Committed independent differential evidence, measured allocation/copy counts, formal clean benchmark, and security review |
| HKDF-SHA-256 | Real extract and expand implementation with borrowed inputs, caller-provided output, one-time prepared HMAC schedule, direct full-block writes, and typed exact-length/overlap failures | RFC 5869 SHA-256 cases 1/2/3, additional fixed fixtures, maximum-length and overlap boundaries, Native/WASI/Embedded WASI execution, explicit façade execution, ASan/TSan/UBSan, and six `-O`/`-Osize` code-generation gates for heap freedom, direct output, and scoped erasure | Independent committed differential evidence, measured allocation/copy counts, formal benchmark, and security review |
| AES-GCM | AES-128/192/256 key schedule, AES block encryption, GCTR, GHASH, caller-owned seal/open spans, and pre-decryption constant-time tag validation | NIST empty-message, single-block, and AAD vectors; round-trip and authentication-failure output-preservation tests; partial-overlap rejection; Native/WASI/Embedded WASI target validation | Independent differential corpus, boundary/limit tests, sanitizer/code-generation review, measured allocation/copy counts, formal benchmark, and security review |
| X25519 | RFC 7748 Montgomery ladder, clamped scalar handling, noncopyable private/shared-secret owners, scoped public-key borrows, and all-zero shared-secret rejection | RFC 7748 and independent deterministic vectors; invalid-length and all-zero-peer failures; Native façade, WASI, and Embedded WASI target validation | Independent differential corpus, malformed-coordinate corpus, sanitizer/code-generation review, measured allocation/copy counts, formal benchmark, and security review |
| HMAC-DRBG | SP 800-90A-style instantiate, generate, additional-input update, reseed, request limit, and noncopyable `SecretBytes` state | Independent deterministic vectors, request-limit failure before mutation, Native/WASI/Embedded WASI target validation | Entropy fault/reseed corpus, sanitizer/code-generation review, measured allocation/copy counts, formal benchmark, and security review |
| Remaining cryptography | Responsibility protocols and typed error boundaries only | Native compilation | Concrete implementations, official vectors, negative/differential/target/performance gates |
| ASN.1 | Strict DER cursor/TLV foundation with limits | Native unit tests and target-validation path | Primitive codecs, writer, PEM, format parsers, fuzzing and full target evidence |
| X.509 | Certificate byte owner and trust-level model only | Native compilation | Certificate parsing, validation, path building, identity, revocation, interoperability |
| TLS/DTLS | Sealed profile and checked action-batch models only | Native model tests and target-validation path | Handshake/record/key-schedule engines, capability suspension, full state/interop/target evidence |
| QUIC TLS integration | Profile actions, checked batch, noncopyable traffic-secret event, and ordered action/secret step output | Nine focused Native tests plus Native/WASI/Embedded WASI target-validation execution | TLS engine integration, capability correlation, RFC vectors, interoperability |
| Platform adapters | Capability protocols only; no adapter product | Protocol compilation | Real entropy/clock/store adapters and per-target semantics |
| `SwiftSSL` façade | Explicit AES-GCM, SHA-256, HMAC-SHA-256, HKDF-SHA-256, and X25519 adapters; lower modules remain separately importable products | AES-GCM, SHA-256, HMAC-SHA-256, HKDF-SHA-256, and X25519 have Native/WASI/Embedded WASI execution | Full application-facing TLS composition and a reviewed stability surface |
| SHA-256 benchmark | Separate manual harness and BoringSSL comparison driver | Exploratory uncommitted measurements only | Quiet-system committed run, allocation/copy evidence, confidence interval, README result |

Protocol declarations, model types, compilation, and a single target probe are not evidence that the corresponding cryptographic or protocol responsibility is complete.
