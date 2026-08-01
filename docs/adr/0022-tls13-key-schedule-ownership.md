# ADR 0022: TLS 1.3 key-schedule ownership

## Status

Accepted. The schedule is a pure derivation component; it does not consume transcript bytes or perform I/O.

## Decision

`TLS13KeySchedule` selects SHA-256 for AES-128-GCM and ChaCha20-Poly1305, and SHA-384 for AES-256-GCM. It performs RFC 8446 `HKDF-Extract`, `Derive-Secret`, and `HKDF-Expand-Label` operations for early, handshake, master, application, exporter, and resumption secrets.

Each derived secret is immediately moved into a noncopyable `SecretBytes` owner. `TLS13HandshakeSecrets`, `TLS13ApplicationSecrets`, and `TLS13ResumptionMasterSecret` expose only scoped borrows, never arrays or escaping pointers. Application traffic and exporter secrets are derived from the transcript through Server Finished. The resumption master secret is a separate owner derived from the later transcript through Client Finished. A caller supplies the PSK, ECDHE output, and transcript digest; the schedule owns no transcript storage and never selects a platform entropy or clock backend.

`TLS13IssuedSessionTicket` pairs the encrypted NewSessionTicket output with the server's move-only `TLS13ResumptionState`. The client independently creates a matching state from its completed transcript. This prevents a callable ticket-sending path from succeeding without returning the PSK state required to accept that ticket.

The schedule validates the hash-sized ECDHE and transcript inputs before any derivation. SHA-256/SHA-384 selection is closed over `TLSCipherSuite`; an unsupported suite cannot silently fall back to another hash.

## Verification

Native TLS model tests cover deterministic SHA-256 and SHA-384 derivation paths, application and resumption ownership, invalid ECDHE lengths, RFC 8448 handshake/application/exporter/resumption known answers, and equality of the server-issued and client-received ticket PSKs. The full target-validation route executes on Native, WASI, and Embedded WASI, and focused AddressSanitizer tests cover the schedule and ticket integration. Broader RFC 8448 record traces, differential comparison, allocation/copy measurement, and release benchmarking remain required.
