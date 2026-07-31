# ADR 0016: SHA-384/512 HMAC and HKDF variants

## Status

Accepted for the symmetric primitive boundary. Differential, sanitizer, and
performance release gates remain open.

## Decision

- HMAC-SHA-384 and HMAC-SHA-512 share a generic 128-byte-block core over the
  corresponding SHA-2 context. Key normalization hashes keys longer than the
  block and wipes normalized key material and contexts.
- HKDF-SHA-384 and HKDF-SHA-512 use the matching HMAC variant for extract and
  expand, enforce the RFC 5869 255-block limit, reject overlap, and write into
  caller-owned output. Partial final blocks use a bounded temporary owner that
  is wiped and deallocated exactly once.
- Public `SwiftSSL` façade types map lower-module primitive errors to the
  existing typed `CryptoInputError` and `HKDFError` contracts.

## Verification

RFC 4231 case 1 and SHA-384/SHA-512 HKDF fixtures are covered by native tests.
The full target validation matrix and independent differential corpus are still
required before release claims.
