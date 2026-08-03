# ADR 0002: Enforce a layered responsibility graph

- Status: Accepted
- Date: 2026-07-31

## Context

Cryptographic libraries become difficult to port and audit when algorithm code, parsers, trust, transport I/O, platform services, and protocol state share mutable objects. Native, WASI, and Embedded implementations also diverge when platform conditionals leak into semantic layers.

## Decision

Use the following acyclic dependency graph:

```text
SSLCore
  -> SSLCrypto
  -> SSLASN1
SSLCrypto + SSLASN1 + SSLCore
  -> SSLX509
SSLCrypto + SSLX509 + SSLCore
  -> SSLTLS
SSLTLS + SSLCrypto + SSLCore
  -> SSLQUIC
SSLCore
  -> SSLPlatform
all modules
  -> SSL facade
```

Lower modules define capability protocols. Platform modules provide implementations. Protocol engines emit capability requests instead of importing platform implementations or invoking asynchronous callbacks.

Each source file has one primary type. Public interfaces are narrow protocols or immutable values; implementations are separate types.

## Consequences

- Core algorithm and state-machine tests run without sockets, files, DNS, or OS trust.
- QUIC packet processing remains outside the TLS library.
- Platform support can be added without changing TLS/X.509 meaning.
- Cycles are prevented by keeping common capabilities and errors in `SSLCore`.
- Convenience composition belongs only in the facade and cannot hide fallback behavior.
