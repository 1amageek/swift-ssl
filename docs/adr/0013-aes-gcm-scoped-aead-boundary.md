# ADR 0013: Use a scoped AES-GCM boundary

## Decision

Implement AES-GCM as a Pure Swift `AuthenticatedCipher` with separate owners for
the AES expanded key schedule and the GHASH subkey. The public `SwiftSSL`
façade translates the internal typed errors without exposing the implementation
storage.

The operation accepts borrowed input spans and a caller-owned mutable output
span. Seal and open permit an exact input start for in-place GCTR, reject partial
input/output overlap before mutation, and never write plaintext before tag
verification succeeds.

## Consequences

- AES-128, AES-192, and AES-256 share one algorithm contract while reporting all
  accepted key sizes in the typed key-length error.
- Native, WASI, and Embedded WASI use the same source and ownership semantics.
- Expanded keys and GHASH state are wiped when their noncopyable owners are
  destroyed.
- The current implementation is a correctness reference path: allocation and
  machine-code budgets still require measurement and optimization before a
  performance or production-security claim.
