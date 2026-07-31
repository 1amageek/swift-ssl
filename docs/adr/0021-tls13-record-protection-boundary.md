# ADR 0021: TLS 1.3 record protection boundary

## Status

Accepted. This ADR covers the record layer only; handshake state and transcript ownership remain separate.

## Decision

`TLS13RecordProtector` owns one traffic key, one IV, and one monotonically advancing sequence number. Keys and IVs are derived from the caller-supplied traffic secret with RFC 8446 HKDF-Expand-Label (`"tls13 key"` and `"tls13 iv"`) using SHA-256 or SHA-384 selected by the cipher suite.

Seal constructs TLSInnerPlaintext in the caller's output buffer, appends the content type and zero padding, emits the fixed legacy outer header (`application_data`, `0x0303`), and authenticates the five-byte header as AEAD associated data. The AEAD is exact-in-place for the plaintext/ciphertext region, so no plaintext staging allocation is required on the seal path. Input/output overlap is rejected before mutation.

Open authenticates and decrypts into a bounded temporary owner. It strips zero padding and requires a valid inner content type before copying plaintext to the caller output. This preserves the no-write-on-authentication-failure and no-write-on-malformed-inner-content contract.

The sequence number is advanced only after success and refuses to wrap. TLS record and plaintext limits are checked before any output mutation.

## Verification

Native TLS model tests exercise all three TLS 1.3 AEAD suites, HKDF-derived keys, TLS header handling, padding, sequence advancement, and authentication failure without modifying the output. RFC 8448 known-answer vectors, interop, target execution, and sanitizer evidence remain required before the record responsibility is complete.
