# ADR 0001: Use a modern Swift-native profile

- Status: Accepted
- Date: 2026-07-31

## Context

BoringSSL exposes modern security functionality through an API whose ownership, error, callback, and compatibility conventions are constrained by C and OpenSSL history. Reproducing that API would preserve the wrong abstraction boundaries and retain legacy code paths that the new package does not require.

The project must replace BoringSSL's security responsibilities for Native, WASI, and Embedded consumers while using Swift ownership and errors directly.

## Decision

The package is an independent Pure Swift implementation. Completeness is measured by the responsibility matrix, official standards, and observable behavior rather than C symbol parity.

The stable protocol profile is TLS 1.3, DTLS 1.3, QUIC TLS integration, modern PKI, and the cryptographic primitives and constructions those responsibilities require. The C API/ABI and historical SSL/TLS/DTLS or cipher paths are absent.

Unsupported, disallowed, and experimental-disabled inputs are distinct typed failures. There is no dynamic fallback to BoringSSL or another system crypto library.

## Consequences

- Existing C/OpenSSL/BoringSSL callers require a Swift-native integration rewrite.
- Public APIs can express ownership, noncopyability, typed failures, and capability suspension.
- No engineering effort is spent preserving obsolete protocol negotiation.
- Deployed certificate verification requirements must be classified explicitly rather than conflated with TLS handshake algorithms.
- The package cannot claim full replacement until every included responsibility passes its verification gates.
