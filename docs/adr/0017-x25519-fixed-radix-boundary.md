# ADR 0017: X25519 fixed-radix boundary

## Status

Accepted for the Pure Swift cryptographic boundary.

## Context

TLS 1.3 and modern HPKE profiles require X25519 key agreement. The API must
support Native, WASI, and Embedded Swift without importing a platform crypto
provider or returning secret material in an ordinary container. The private
key and shared secret therefore need noncopyable owners, while public keys can
remain ordinary immutable bytes.

## Decision

- Implement RFC 7748 X25519 with a Montgomery ladder and a 16-limb radix-
  2^16 field representation reduced modulo `2^255 - 19`.
- Clamp the scalar at the primitive boundary and mask the most significant bit
  of the peer u-coordinate during decoding.
- Reject an all-zero shared secret with the typed `invalidPeerKey` failure.
- Expose private keys and shared secrets through `SecretBytes`-backed,
  noncopyable owners. Public keys use `OwnedBytes` and scoped `Span` borrows.
- Keep the only raw-buffer borrow for the static base point inside a
  `withUnsafeBufferPointer` closure; no pointer or span escapes that closure.
- Expose the same implementation through the `SwiftSSL` façade without a
  second arithmetic implementation or a fallback backend.

## Verification

The boundary has RFC 7748 public-key coverage, an independent shared-secret
fixture, four deterministic field/arithmetic vectors, invalid-length failures,
all-zero peer rejection, Native façade execution, and the pinned WASI and
Embedded WASI target validation paths. Differential, sanitizer/code-generation,
allocation, and release benchmark gates remain open before the responsibility
is marked release-complete.

## Consequences

The implementation is source-portable and keeps ownership visible in the API,
but the scalar fixed-radix path is currently a correctness-first reference
implementation. Any later limb or platform optimization must preserve the
same vectors, failure behavior, and scoped unsafe boundary before replacing it.
