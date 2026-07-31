# ADR 0006: Separate stable standards from experimental algorithms

- Status: Accepted
- Date: 2026-07-31

## Context

Post-quantum TLS, HPKE, and hybrid constructions evolve through drafts while primitive standards and wire standards stabilize at different times. Treating draft identifiers as permanent API risks silently changing the meaning of persisted or negotiated configuration.

## Decision

Final standards use stable identifiers. Draft constructions and wire groups are exposed only through an experimental namespace containing the exact draft revision and require explicit policy opt-in.

Updating a revision creates a new identifier. It does not reinterpret the old identifier. Removed or insecure drafts remain rejected and do not route to a newer construction.

Primitive conformance and protocol eligibility are separate. For example, an ML-DSA primitive can be complete while its TLS or X.509 use remains experimental-policy gated.

## Consequences

- Configuration remains reproducible across library updates.
- Interoperability experiments do not become silent production defaults.
- Each revision requires new vectors, negative tests, interop evidence, and migration documentation.
- FIPS primitive publication or test success is not represented as module validation.
