# ADR 0015: SHA-384 and SHA-512 context boundary

## Status

Accepted for the Pure Swift hash boundary. Optimized architecture-specific
compression and differential corpus remain release gates.

## Decision

- `SHA512Context` owns the eight-word state, 128-byte pending block, and
  checked byte counter. It implements the same borrowed `Span` and caller-owned
  `MutableSpan` contract as SHA-256.
- `SHA384Context` reuses the SHA-512 compressor with the FIPS 180-4 SHA-384
  initial state and emits the first 48 bytes of the finalized digest.
- `SwiftSSL` exposes separate `SHA384` and `SHA512` façade types and contexts;
  lower-module types are not re-exported wholesale.
- A context rejects an incorrectly sized output before mutating it. Clone is an
  independent snapshot and can be finalized separately.
- The current compressor is scalar and uses bounded schedule storage. No C,
  Foundation, platform hash API, or silent fallback is permitted.

## Verification

FIPS 180-4 `abc` vectors, incremental clone equivalence, and output-length
failure are covered by `SHA512Tests`; Native façade, WASI, and Embedded WASI
target validation exercise both algorithms. Differential long-message,
sanitizer, code-generation, allocation, and benchmark evidence remains open.
