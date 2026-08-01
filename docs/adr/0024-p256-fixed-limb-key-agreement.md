# ADR 0024: Fixed-limb P-256 key agreement

## Status

Superseded by ADR 0036. The callable P-256 secret-key and ECDH surface was
removed from the modern profile.

## Context

Modern certificate ecosystems still require NIST P-256 even when a TLS profile
prefers X25519. A platform cryptography dependency cannot be used by the
WASI or Embedded Swift targets, and a general-purpose mutable big integer
would obscure ownership and range guarantees.

## Decision

`SwiftSSLCrypto.P256` uses eight fixed 32-bit limbs for field and scalar
values. Field multiplication uses a fixed 512-bit product followed by a
bounded reduction modulo the P-256 prime. Jacobian points avoid an inversion
per scalar-multiplication step; only the final affine conversion inverts the
Z coordinate. Private scalars are owned by `SecretBytes`, public points are
validated as SEC1 uncompressed points, and shared secrets are exposed only by
a scoped borrow from `SecretBytes`.

The public façade mirrors the ownership and error contracts without exporting
the arithmetic types. The primitive is validated independently with a field
arithmetic fixture, deterministic generator/public-key vectors, a two-party
ECDH vector, and invalid scalar/point cases. Native, WASI, and Embedded WASI
target validation use the same source path.

## Consequences

- P-256 ECDH does not depend on BoringSSL, CryptoKit, or Foundation.
- P-384/P-521, ECDSA signing/verification, and TLS key-share negotiation remain
  explicit follow-up responsibilities; this ADR does not claim a complete
  public-key profile.
- The generic reduction is intentionally simple and currently slower than a
  dedicated Montgomery implementation, especially under the WASM interpreter.
  A performance replacement must preserve the vectors, ownership boundaries,
  and target validation before it can replace this implementation.
- This standalone implementation is not a release-gate claim: scalar
  multiplication and field normalization still require a dedicated
  constant-time audit before use in a production TLS or certificate path.
