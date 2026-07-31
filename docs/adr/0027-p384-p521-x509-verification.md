# ADR 0027: Fixed-width P-384/P-521 verification at the X.509 boundary

## Status

Accepted as a validation-only implementation; release gating remains open.

## Context

The certificate parser already accepted the SEC1 named-curve identifiers for
P-384 and P-521, but ECDSA-with-SHA2 verification stopped at P-256. That left a
modern X.509 path incomplete even though the wire and DER identifiers were
available.

## Decision

Add fixed-width 32-bit-limb ECDSA verification for P-384 and P-521 in
`SwiftSSLCrypto`. The implementation accepts borrowed uncompressed SEC1 public
keys and fixed-width `r || s` signatures. `SwiftSSLX509.X509Certificate` owns
DER signature decoding and selects the curve only when the signature and SPKI
algorithm identifiers agree.

The implementation intentionally remains outside TLS certificate selection
until the constant-time audit, independent differential corpus, sanitizer,
allocation/copy, and performance gates are recorded. A marker remains beside
the callable boundary so a validation success cannot be mistaken for release
readiness.

## Consequences

- P-384 and P-521 certificates can now be parsed and cryptographically checked
  without a platform crypto dependency.
- X.509 owns DER integer canonicalization; the crypto layer owns curve arithmetic.
- The current generic limb backend is a bounded validation path and is not yet a
  constant-time production backend.
- ECDSA signing, RSA-PSS, and TLS selection remain separate responsibilities.

```mermaid
flowchart LR
    DER[Certificate DER] --> X509[X509Certificate]
    X509 -->|strict r/s decode| Raw[Fixed-width r||s]
    X509 -->|SPKI curve| Select{P-256 / P-384 / P-521}
    Select --> Crypto[SwiftSSLCrypto verifier]
    Raw --> Crypto
    Crypto --> Result[typed success or signature failure]
    Crypto -. release gates pending .-> Gate[constant-time / differential / sanitizer / benchmark]
```
