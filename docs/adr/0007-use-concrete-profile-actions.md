# ADR 0007: Use concrete actions for each transport profile

- Status: Accepted
- Date: 2026-07-31

## Context

TLS stream, DTLS 1.3, and QUIC integration share handshake semantics but do not have the same legal effects. A generic action enum parameterized only by a channel type permits unrelated cases to appear in every profile. For example, it can represent TLS application data in the QUIC profile or a DTLS flight flush in the stream profile even though those operations are invalid there.

The pinned Swift 6.4 WASI baseline also exposes a runtime defect when a `ContiguousArray` stores a generic enum with associated values. Debug builds trap while reserving capacity. Optimized builds complete allocation and trap during release. Equivalent concrete enums execute correctly.

## Decision

The package-internal `TLSProfile` protocol associates one concrete action type that conforms to the package-internal `TLSBatchAction` protocol. The package defines distinct public `TLSStreamAction`, `DTLSAction`, and `QUICTLSAction` enums. External modules cannot add profiles or action conformances to the sealed production engine.

Public `TLSStreamActionBatch`, `DTLSActionBatch`, and `QUICTLSActionBatch` values own one immutable byte backing and an array of their concrete action type. Their construction is package-restricted and uses one shared package-internal range validator. External conformances cannot bypass validation.

Profile-specific effects remain on their profile action:

- stream actions own TLS record emission and TLS application-data delivery;
- DTLS actions own datagram emission and flight control;
- QUIC TLS actions own encryption-level handshake bytes and never expose TLS records or TLS application data.
- QUIC handshake levels exclude 0-RTT because QUIC CRYPTO frames are not legal at that level. Traffic-secret levels use a separate type.

## Consequences

- Illegal cross-profile effects are unrepresentable in public action values.
- Action handling uses closed, concrete enum dispatch without type erasure on the hot path.
- Public batch construction cannot trust an externally supplied range descriptor.
- The pinned Native, WASI, and Embedded WASI targets use the same source and ownership contract.
- Some structurally similar cases are intentionally repeated to keep semantic ownership explicit.
- A future compiler fix does not by itself justify merging the action types; the responsibility boundary remains the primary reason for the design.

## Verification

The target validation executable constructs, validates, releases, and follows a concrete action batch with additional allocations. It must run in Debug mode on Native, WASI, and Embedded WASI. The minimized generic-enum failure is retained in analysis evidence, not in the production package.
