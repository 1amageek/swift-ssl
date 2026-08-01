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
| Hash | SHA-256, SHA-384, SHA-512 | Required | `SwiftSSLCrypto`; callable implementations are integrated with HMAC/HKDF, TLS 1.3, and supported certificate-signature verification |
| SHA-3/XOF | SHA3-256/512, SHAKE128/256 | Required | `SwiftSSLCrypto`; FIPS 202 sponge and incremental contexts are implemented; PQ and protocol integration remain separate responsibilities |
| Additional hash | BLAKE2 variants still justified by modern callers | Later | Separate from TLS completion; no BoringSSL symbol compatibility |
| MAC | HMAC-SHA-256/384/512 | Required | `SwiftSSLCrypto` and façade implementations with constant-time tag verification |
| KDF | HKDF-SHA-256/384/512 | Required | Extract/expand implementations; TLS and HPKE labels remain separate constructions |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | Required | AES-GCM and ChaCha20-Poly1305 callable implementations protect all three TLS 1.3 cipher suites; open failure exposes no plaintext |
| Classical KEX | X25519 | Required | `SwiftSSLCrypto.X25519` is the only secret-bearing classical key-agreement capability in the modern profile |
| Classical signature | Ed25519 | Required | `Ed25519` conforms to separate message-signing and verification protocols with noncopyable private and owned validated public keys |
| Certificate signature verification | ECDSA P-256/384/521; RSA-PSS SHA-256/384/512 | Policy-gated | Verification-only public-input capabilities; no NIST or RSA private-key type and no TLS signer exists |
| Certificate compatibility verification | RSA PKCS #1 v1.5 with approved SHA-2 hashes | Policy-gated | Verification only for deployed PKI; never a TLS CertificateVerify signer |
| ML-KEM | ML-KEM-768 and ML-KEM-1024 | Required | FIPS 203 semantics; implicit rejection for correctly sized ciphertext |
| ML-DSA | ML-DSA-44/65/87 | Required primitive | FIPS 204; TLS/X.509 use remains wire-policy gated |
| TLS hybrid | X25519MLKEM768 pinned to `draft-ietf-tls-ecdhe-mlkem-05` | Experimental until standardized | Callable role-specific key exchange is integrated with Stream TLS and QUIC under an explicit revision policy; draft Kyber groups are excluded |
| HPKE | RFC 9180 X25519 DHKEM Base, PSK, Auth, and AuthPSK modes with HKDF-SHA256/384/512 and AES-GCM/ChaCha20-Poly1305 | Required | X25519 profile is callable with distinct sender/recipient contexts, sequence-bound nonces, a wiped exporter-secret owner, typed failures, RFC A.2 vectors for all modes, and native target validation; P-256 DHKEM and ECH remain separate protocol work |
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
| SPKI and PKCS #8 | Required | Strict structural parsers own immutable DER plus checked key ranges; RFC 5915 ECPrivateKey decoding validates version, curve parameters, scalar-sized encoding, optional public key, and PKCS #8 outer/inner curve agreement as a format responsibility; it is not a TLS signing-key factory |
| Encrypted PKCS #8 | Required | Explicit modern encryption profiles and password handling policy |
| PKCS #12 | Required | Certificate/key interchange without reproducing legacy OpenSSL APIs |
| CMS/PKCS #7 certificate containers | Required subset | Parse and emit the certificate-container responsibility needed by current ecosystems |
| X.509 certificate and extension parse | Required | Immutable DER owner plus ranges; syntax validity is not path validity |
| RFC 5280 path building and validation | Required | `X509PathValidator` performs bounded unordered search, loop detection, issuer/subject DER-name matching, validity windows, trust-anchor selection, BasicConstraints CA/pathLen, optional keyCertSign, and signature/algorithm policy; revocation and advanced policy remain separate |
| Service identity | Required | SAN-only matching; no Common Name fallback; `X509Certificate.matchesDNSName` implements ASCII DNS labels and one-label left-most wildcards |
| Trust store | Required protocol | Caller-supplied immutable trust records; platform adapters are separate |
| CRL and OCSP | Required | Acquisition, evidence validation, and hard/soft-fail policy separated |
| Certificate Transparency inputs | Required | SCT parsing and verification capability; log-list acquisition is external |
| Delegated credentials | Required | TLS policy-gated modern extension |
| Raw public keys | Required | Explicit authentication profile, never confused with X.509 trust |
| Certificate compression | Required | Bounded decompression and transcript-correct encoding |

## 4. Secure transport responsibility

| Responsibility | Status | Boundary |
|---|---|---|
| TLS 1.3 stream | Required | `TLS13ClientHandshake` and `TLS13ServerHandshake` adapt TLS records to the shared record-independent core; the adapter owns framing, AEAD protectors, application records, encrypted post-handshake tickets, and KeyUpdate record transitions, while the core owns transcript, authentication, key schedule, Finished, resumption, and traffic-secret evolution |
| TLS resumption | Required | Immutable, identity-bound, expiring, single-use state plus PSK ClientHello/binder integration, server ticket-age validation, and resumed-handshake transcript integration; cross-process replay coordination and persistence remain external policy |
| TLS 0-RTT | Required | Separate from resumption; explicit replay policy; no automatic replay |
| ECH RFC 9849 | Required | HPKE inner/outer and retry outcome; DNS and retry transport external |
| DTLS 1.3 | Required | Epoch/sequence/replay, fragmentation, ACK, flight and timer state, CID; `DTLS13ReplayWindow` implements bounded per-epoch replay tracking |
| DTLS-SRTP | Required | Negotiation/exporter boundary; media transport external |
| QUIC RFC 9001 | Required | TLS handshake bytes and secret events only; `QUICInitialSecrets` implements RFC 9001 v1 Initial HKDF derivation, `QUICTLSHandshakeStream` owns bounded per-level ordered delivery, and `QUICTLSClientHandshake` / `QUICTLSServerHandshake` connect zero-copy message borrows to record-independent TLS state machines and directional secret effects |
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
- Draft algorithms expose an experimental policy, and their exact revision is pinned by an ADR and package release. A public wire name registered without a draft suffix may retain that name, but its semantics are never silently reinterpreted.
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
| X25519 | RFC 7748 Montgomery ladder, clamped scalar handling, noncopyable private/shared-secret owners, caller-owned in-place outputs, fixed-base table multiplication, scoped public-key borrows, and transactional all-zero shared-secret rejection | RFC 7748 and independent deterministic vectors; invalid-length and all-zero-peer output-preservation failures; Hybrid Native/WASI/Embedded execution and focused ASan; committed formal zero-allocation/zero-dynamic-copy evidence for caller-owned public/shared outputs | Broader independent differential and malformed-coordinate corpora, automated constant-time code-generation gate, and security review |
| Ed25519 | Noncopyable private seed, owned validated public key, separate signing/verification protocols, fixed-iteration scalar reduction, and mask-selected secret scalar multiplication | RFC 8032 signing/verification, modified-message and noncanonical-scalar failures, Native/WASI/Embedded façade verification, Native TLS/Core tests, dedicated three-target QUIC/TLS authentication, focused ASan over 11 tests, and manual optimized ARM64 control-flow inspection | Broader official corpus, automated constant-time code-generation gate, TSan/UBSan, allocation/copy measurement, interoperability, benchmark, and security review |
| NIST ECDSA verification | Verification-only P-256/P-384/P-521 fixed-width arithmetic with typed public-key owners and no secret-key API | Independent raw vectors and mutation failures, real X.509 fixtures, and dedicated Native/WASI/Embedded Release success/failure routes | Broader differential corpus, sanitizer coverage, allocation/copy measurement, benchmark, and security review; public-input verification does not require a secret-dependent timing contract |
| HMAC-DRBG | SP 800-90A-style instantiate, generate, additional-input update, reseed, request limit, and noncopyable `SecretBytes` state | Independent deterministic vectors, request-limit failure before mutation, Native/WASI/Embedded WASI target validation | Entropy fault/reseed corpus, sanitizer/code-generation review, measured allocation/copy counts, formal benchmark, and security review |
| SHA3/SHAKE | FIPS 202 Keccak-f[1600] sponge with incremental SHA3-256/512 and SHAKE128/256 contexts, scoped output, and strict length checks | FIPS 202 known answers, clone equivalence, output-preservation failure test, Native/WASI/Embedded WASI target validation | Independent differential corpus, long-message boundary corpus, sanitizer/code-generation review, formal benchmark, and security review |
| ML-KEM-768/1024 | Callable FIPS 203 KEM and in-place KEM implementations with noncopyable private/shared-secret owners, immutable expanded keys, implicit rejection, SIMD NTT, and two-stream Keccak | NIST ACVP/TR1 fixtures, arithmetic differential/boundary tests, typed no-write failures, focused ASan, six optimized secure-wipe code-generation configurations, Native/WASI/Embedded WASI façade execution, pinned-BoringSSL bidirectional interoperability, a committed formal 30-pair benchmark whose six workloads pass the `1.10x` lower-confidence-bound gate, and a committed linear allocation/dynamic-copy artifact for all six paths | Broader external corpus, automated constant-time review, TSan/UBSan availability statement, and security review |
| ML-DSA-65 | Callable FIPS 204 contextual randomized signature and in-place signature implementation with a noncopyable private-key owner, immutable expanded secret coefficients, synchronized immutable public expansion, scoped raw signing workspace, SIMD NTT, and two-stream Keccak | NIST ACVP key-generation fixture, Wycheproof seeded-signature fixture, success/failure/domain-separation tests, Native/WASI/Embedded WASI façade execution, ASan-instrumented XCTest and façade execution, pinned-BoringSSL bidirectional signature interoperability and mutation rejection, a committed formal allocation/dynamic-copy artifact, and an exploratory 30-pair benchmark whose three workloads exceed the `1.10x` lower-confidence-bound target | Commit and rerun the formal timing gate, broader external corpus, automated constant-time review, TSan/UBSan availability statement, ML-DSA-44/87, and security review |
| X25519MLKEM768 TLS key exchange | Role-specific one-shot client/server protocols, exact draft-05 share ordering and lengths, ML-KEM encapsulation-key validation and implicit rejection, X25519 all-zero rejection, noncopyable private/secret owners, borrowed received shares, and direct final-owner output | Native key-exchange/Core/Stream/QUIC success and failure tests; Native/WASI/Embedded dedicated runtime execution; dedicated Hybrid ASan execution; committed formal bidirectional pinned-BoringSSL interoperability and 30-pair timing artifact passing the `1.10x` lower-confidence-bound gate; committed formal steady-state allocation/dynamic-copy artifact with exact linear budgets | Broader corpus, a second independent peer, automated constant-time review, and security review |
| Remaining cryptography | ML-DSA-44/87 and additional approved hybrid constructions remain outside the callable implementation; ML-DSA-65, ML-KEM, X25519MLKEM768, and X25519 HPKE are callable; RSA-PSS and NIST ECDSA are verification-only | Native vectors cover FIPS 204 ML-DSA-65, FIPS 203, and RFC 9180 X25519 HPKE; ML-DSA-65 and X25519MLKEM768 have production-path and three-target execution; RSA-PSS has Montgomery differential, sanitizer, and three-target runtime evidence; NIST ECDSA has independent verification vectors | ML-DSA-44/87, ECH, additional approved hybrid constructions, and their completion gates |
| ASN.1 | Strict DER cursor/TLV, canonical primitive codecs, bounded writer, strict RFC 7468 PEM codec, SPKI, unencrypted PKCS #8, and RFC 5915 ECPrivateKey decoder | Native unit tests for cursor, primitive values, transactional writer failures, canonical Base64, CRLF, malformed input, output limits, RFC 5915 P-256 parsing, and curve mismatch | Encrypted PKCS #8/PKCS #12/CMS codecs, fuzzing and full target evidence |
| X.509 | Certificate/TBSCertificate/Validity/signature/SPKI structural parser, issuer-key signature verification, Ed25519, verification-only ECDSA P-256/P-384/P-521 and RSA-PSS-with-SHA2 signatures, strict v3 extension parsing, SPKI, unencrypted PKCS #8 owners, and bounded trust-anchor path validation | Native X509 tests for certificate ranges/time fields, Ed25519, ECDSA P-256/P-384/P-521, and RSA-PSS signatures, modified-signature failures, RSA key-type mismatch, real leaf/root path validation with SAN, duplicate extensions, X25519 SPKI, and PKCS #8 version failures; RSA-PSS has ASan and Native/WASI/Embedded runtime evidence | Revocation, advanced RFC 5280 policy, broader differential corpus, target evidence, and interoperability |
| TLS/DTLS | One record-independent TLS 1.3 semantic core shared by Stream and QUIC, narrow client/server protocols, HKDF key schedule, AEAD Stream record adapter, synchronous X25519 or X25519MLKEM768 key exchange with Ed25519 authentication for all three TLS 1.3 AEAD suites, encrypted NewSessionTicket transport, PSK extension/binder primitives, server ticket-age validation, single-use PSK resumption, post-handshake KeyUpdate, SAN-only identity helper, and bounded DTLS replay window | Native classical and Hybrid full Stream/Core/QUIC handshake completion, Ed25519 CertificateVerify with X.509 fixtures, certificate-window rejection, ticket age/binder rejection, encrypted ticket round trip and resumption-state derivation, KeyUpdate request/response and post-update data, all suite round trips, focused AddressSanitizer execution, replay-window boundaries, and dedicated Native/WASI/Embedded WASI Hybrid key-exchange plus QUIC/core runtime validation | RFC 8448 corpus, 0-RTT, external credential/trust capabilities, DTLS flights/ACK/timers/epochs, broader allocation/copy measurement, and full-handshake external interoperability |
| QUIC TLS integration | Profile actions, checked batch, noncopyable traffic-secret event, ordered action/secret step output, RFC 9001 v1 Initial derivation, bounded per-level CRYPTO reassembly, zero-copy message delivery, record-independent full and resumed TLS handshakes, and role-correct handshake/1-RTT secret delivery | Native full-handshake, PSK-resumption, tampered-Finished, wrong-epoch, out-of-order CRYPTO, overlap-conflict, and directional-secret tests; three guarded core/adapter repetitions; focused AddressSanitizer execution; dedicated Native/WASI/Embedded WASI full-handshake runtime validation with directional-secret comparison | QUIC transport-parameter and ALPN negotiation, packet protection, allocation/copy measurement, fuzzing, and external interoperability |
| Platform adapters | Capability protocols only; no adapter product | Protocol compilation | Real entropy/clock/store adapters and per-target semantics |
| `SwiftSSL` façade | Explicit AES-GCM, SHA-2, SHA-3/SHAKE, HMAC-SHA-256, HKDF-SHA-256, X25519, Ed25519, ML-KEM-768/1024, ML-DSA-65, and verification-only P-256 ECDSA adapters; lower modules remain separately importable products | Symmetric, hash/MAC/KDF, X25519, Ed25519, ML-KEM, ML-DSA-65 success/failure, and P-256 verification have Native/WASI/Embedded WASI execution | Full application-facing TLS composition and a reviewed stability surface |
| SHA-256 benchmark | Separate manual harness and BoringSSL comparison driver | Formal 30-pair Native measurement with confidence intervals is recorded in README; the 1.10x release gate failed for every workload; ADR 0037 and a manual Swift/Clang code-generation probe isolate the ARM64 tied-operand register-allocation boundary | Obtain a compiler/public-intrinsic path that removes the recurrent tied copy without leaving Pure Swift, then repeat the formal gate; allocation/copy and WASM/Embedded measurements remain open |

Protocol declarations, model types, compilation, and a single target probe are not evidence that the corresponding cryptographic or protocol responsibility is complete.
