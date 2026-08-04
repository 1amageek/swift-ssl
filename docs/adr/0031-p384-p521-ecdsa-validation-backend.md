# ADR 0031: P-384/P-521 ECDSA Validation Backend

- Status: Accepted; release qualification remains pending
- Date: 2026-08-01

## Context

The fixed-width Weierstrass implementation provides RFC 6979 signing, raw
`r || s` verification, compressed-point decoding, and ECDH for NIST P-384 and
P-521. Public keys validate SEC1 encodings and private keys keep secret material
in noncopyable storage. The arithmetic is still variable-time and has not
passed the constant-time, differential, sanitizer, allocation, and performance
gates required for protocol authentication.

## Decision

Expose P-384/P-521 ECDSA and ECDH as explicit cryptographic surfaces. The
default TLS authentication remains Ed25519/P-256, while callers may select an
NIST curve deliberately through the crypto facade. The arithmetic remains
release-gated until constant-time, differential, sanitizer, allocation,
performance, and interoperability evidence is recorded.

```mermaid
flowchart LR
    Input[Private scalar and message digest] --> RFC[RFC 6979 HMAC state]
    RFC --> Sign[Fixed-width P-384/P-521 signing]
    Sign --> Vector[RFC vector and round-trip tests]
    Vector --> Gates{Constant-time, differential, sanitizer, performance}
    Gates -->|pending| Explicit[Explicit caller selection with release gate]
    Gates -->|passed| Qualified[Release-qualified TLS authentication]
    Explicit --> TLS[TLS CertificateVerify]
```

## Consequences

- RFC 6979 state performs both update rounds and rejects out-of-range nonce
  candidates instead of reducing them modulo the group order.
- Temporary DRBG inputs and state are erased before release; public signatures
  remain ordinary owned output.
- P-384/P-521 signing and key agreement are callable through the pure Swift
  backend and facade. The remaining gates are tracked in the responsibility
  matrix rather than hidden behind an implicit fallback.
