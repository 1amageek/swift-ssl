# ADR 0027: Fixed-width P-384/P-521 verification at the X.509 boundary

## Status

Accepted for production certificate-signature verification under ADR 0036.

## Context

The certificate parser already accepted the SEC1 named-curve identifiers for
P-384 and P-521, but ECDSA-with-SHA2 verification stopped at P-256. That left a
modern X.509 path incomplete even though the wire and DER identifiers were
available.

## Decision

Add fixed-width 32-bit-limb ECDSA verification for P-384 and P-521 in
`SSLCrypto`. The implementation accepts borrowed uncompressed SEC1 public
keys and fixed-width `r || s` signatures. `SSLX509.X509Certificate` owns
DER signature decoding and selects the curve only when the signature and SPKI
algorithm identifiers agree.

The implementation remains outside TLS signing and CertificateVerify
selection. Its public key, digest, signature, and result are public inputs, so
the variable-time arithmetic does not cross a secret boundary. Independent
differential, sanitizer, target, allocation/copy, performance, and security
review gates remain release requirements for correctness and robustness.

## Consequences

- P-384 and P-521 certificates can now be parsed and cryptographically checked
  without a platform crypto dependency.
- X.509 owns DER integer canonicalization; the crypto layer owns curve arithmetic.
- The current generic limb backend is bounded verification-only arithmetic.
- ECDSA signing is absent; RSA-PSS verification and TLS Ed25519 signing are
  separate capabilities.

```mermaid
flowchart LR
    DER[Certificate DER] --> X509[X509Certificate]
    X509 -->|strict r/s decode| Raw[Fixed-width r||s]
    X509 -->|SPKI curve| Select{P-256 / P-384 / P-521}
    Select --> Crypto[SSLCrypto verifier]
    Raw --> Crypto
    Crypto --> Result[typed success or signature failure]
    Crypto -. release gates pending .-> Gate[differential / sanitizer / targets / benchmark]
```
