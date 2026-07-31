# ADR 0014: ChaCha20-Poly1305 boundary

## Status

Accepted for the Pure Swift cryptographic boundary. Production performance and
full TLS integration remain separate completion gates.

## Context

TLS 1.3 requires ChaCha20-Poly1305 in addition to AES-GCM. The implementation
must run through the same Native, WASI, and Embedded source boundary, preserve
borrowed input lifetime, support exact in-place operation, and never expose
plaintext before tag verification.

## Decision

- `SwiftSSLCrypto.ChaCha20Poly1305` owns the parsed 256-bit key and conforms to
  the existing `AuthenticatedCipher` protocol.
- `SwiftSSL.ChaCha20Poly1305` is the public façade adapter; it maps only the
  typed `AEADError` contract and does not expose the lower implementation.
- ChaCha20 uses the RFC 8439 96-bit nonce and counter 1 for payload blocks.
- Poly1305 uses the counter-0 one-time key and authenticates
  `AAD || pad16(AAD) || ciphertext || pad16(ciphertext) ||
  le64(len(AAD)) || le64(len(ciphertext))`, where lengths are bytes.
- Authentication is verified before opening ciphertext. Exact same-start input
  and output is supported; partial overlap and AAD/output overlap fail before
  mutation.
- Secret key, one-time key, Poly1305 state, and bounded block temporaries are
  wiped at owner or scope end. Unsafe access is confined to scoped buffer
  closures and no pointer escapes.

## Verification

The RFC 8439 known-answer vector, exact in-place seal/open, authentication
failure no-write behavior, and partial-overlap rejection are covered by
`ChaCha20Poly1305Tests`. Native façade and target validation include the empty
message vector. Differential corpus, sanitizer/code-generation review, and the
formal BoringSSL benchmark remain release gates.

## Consequences

This decision supplies the second TLS 1.3 AEAD implementation without retaining
BoringSSL or a C ABI. The current scalar reference path deliberately keeps
bounded temporary arrays; allocation/copy measurements and optimized backend
work must be completed before a performance claim is made.
