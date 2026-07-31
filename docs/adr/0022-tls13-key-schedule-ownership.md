# ADR 0022: TLS 1.3 key-schedule ownership

## Status

Accepted. The schedule is a pure derivation component; it does not consume transcript bytes or perform I/O.

## Decision

`TLS13KeySchedule` selects SHA-256 for AES-128-GCM and ChaCha20-Poly1305, and SHA-384 for AES-256-GCM. It performs RFC 8446 `HKDF-Extract`, `Derive-Secret`, and `HKDF-Expand-Label` operations for early, handshake, master, application, exporter, and resumption secrets.

Each derived secret is immediately moved into a noncopyable `SecretBytes` owner. `TLS13HandshakeSecrets` and `TLS13ApplicationSecrets` expose only scoped borrows, never arrays or escaping pointers. A caller supplies the PSK, ECDHE output, and transcript digest; the schedule owns no transcript storage and never selects a platform entropy or clock backend.

The schedule validates the hash-sized ECDHE and transcript inputs before any derivation. SHA-256/SHA-384 selection is closed over `TLSCipherSuite`; an unsupported suite cannot silently fall back to another hash.

## Verification

Native TLS model tests cover deterministic SHA-256 and SHA-384 derivation paths, application secret ownership, and invalid ECDHE lengths. RFC 8448 transcript vectors, differential comparison, target execution, and sanitizer evidence remain required before handshake integration is complete.
