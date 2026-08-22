# ADR 0021: TLS 1.3 record protection boundary

## Status

Accepted. This ADR covers the record layer only; handshake state and transcript ownership remain separate.

## Decision

`TLS13RecordProtector` owns one traffic key, one IV, and one monotonically advancing sequence number. Keys and IVs are derived from the caller-supplied traffic secret with RFC 8446 HKDF-Expand-Label (`"tls13 key"` and `"tls13 iv"`) using SHA-256 or SHA-384 selected by the cipher suite.

Seal writes the fixed legacy outer header (`application_data`, `0x0303`) and
authenticates it as AEAD associated data. Segmented AEAD borrows the caller's
application payload and treats the content type plus zero padding as a virtual
suffix, writing ciphertext and tag directly into the caller's final record
destination. TLSInnerPlaintext is never materialized. Input/output overlap is
rejected before mutation.

Open authenticates and decrypts directly into unpublished caller-owned output.
It strips zero padding and requires a valid inner content type before returning
the initialized plaintext range. Authentication or malformed-inner-content
failure wipes the touched destination, so no unauthenticated bytes are
published and no intermediate plaintext owner is required.

The sequence number is advanced only after success and refuses to wrap. TLS
record and plaintext limits, output capacity, and overlap are checked before
state mutation. An undersized destination is retryable with the same protector
state.

## Verification

Native TLS model tests exercise all three TLS 1.3 AEAD suites, HKDF-derived keys,
TLS header handling, segmented suffixes at block boundaries and maximum payload,
padding, transactional sequence advancement, retryable sizing/overlap failure,
and authentication/malformed-inner-content zeroization. Differential tests
compare segmented AES-GCM and ChaCha20-Poly1305 output with their contiguous
reference paths. Native ASan plus matching WASI and Embedded WASI executable
probes are required cross-target evidence.
