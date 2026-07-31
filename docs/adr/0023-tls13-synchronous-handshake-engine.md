# ADR 0023: Synchronous TLS 1.3 handshake engine boundary

## Context

The record protector, key schedule, and handshake message codecs were callable
but had no state owner that connected them into a complete client/server path.
Leaving those pieces as independent models made it possible to report a
successful build without exercising a TLS handshake.

## Decision

`TLS13ClientHandshake` and `TLS13ServerHandshake` are single-owner synchronous
state machines. They consume complete TLS records and return an owned
`TLS13HandshakeOutput` whose actions reference one byte backing. The initial
profile is deliberately closed over X25519 key exchange, Ed25519 certificate
authentication, and all three TLS 1.3 AEAD suites. Unsupported cipher suites and
credentials are typed failures; there is no fallback to another algorithm.

The engine also owns post-handshake KeyUpdate: a KeyUpdate record is sealed
with the current write secret, the next traffic secret is installed afterward,
and the peer's read secret is advanced before any requested response is emitted.

The client uses explicit public-key pinning as its trust boundary and requires
the caller to supply a `VerificationInstant`; the certificate validity window
is checked before signature and CertificateVerify acceptance. The server makes
the same validity check and validates that the supplied Ed25519 signing key
matches the certificate SPKI. This is a deliberately narrow trust profile,
not a replacement for path building or a platform trust store.
Network I/O, trust-store lookup, asynchronous private-key providers, record
fragment buffering, resumption, 0-RTT, and ECH remain separate responsibilities
and are not represented as successful behavior by this engine.

The handshake copies only the fixed 32-byte ECDHE result into the key-schedule
boundary and wipes that temporary. Record payloads are copied into bounded
handshake owners because a step may process several coalesced records; the
record protector remains the zero-copy hot-path implementation for application
traffic.

## Verification

The deterministic client/server fixture covers the complete wire path through
server CertificateVerify, both Finished messages, and application-secret
installation. A malformed or authenticated record must produce a typed failure
and leave the engine unestablished. Differential and interoperability evidence
remain release gates.
