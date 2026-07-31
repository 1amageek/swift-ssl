# ADR 0003: Separate borrowed bytes, owned bytes, and secret owners

- Status: Accepted
- Date: 2026-07-31

## Context

Repeated conversion among `Array`, `Data`, strings, and parser objects creates allocations and obscures lifetime. Conversely, exposing raw pointers broadly makes ownership and escape analysis unauditable. Secret material also requires stronger copying and destruction rules than public wire bytes.

## Decision

Use three distinct categories:

1. ordinary owned contiguous bytes for wire messages and encodings;
2. nonescaping `Span`/`MutableSpan` borrows for synchronous processing;
3. a noncopyable, uniquely allocated secret owner with scoped borrows and wipe-before-free destruction.

Parsed DER models own a single immutable buffer and store checked ranges. Action batches own a single output buffer and actions store ranges. Incomplete protocol fragments may be copied only into a bounded pending-input owner when they must survive a call.

Unsafe memory operations are internal, scoped, and documented with ownership, deallocation, lifetime, count, alignment, initialization, binding, aliasing, and synchronization invariants.

The initial portability guarantee for secrets is wipe-before-free. The public API does not promise page locking, nonpageability, or a secure heap. A zeroization guarantee is accepted only after generated-code inspection on every baseline target.

## Consequences

- Hot paths can meet explicit copy/allocation budgets.
- Borrowed views cannot outlive their owners through supported APIs.
- Secret-bearing aggregate types may also need to be noncopyable.
- Convenience conversion to Foundation types is restricted to explicit outer boundaries.
- Performance claims require measured copies and allocations, not merely pointer-based implementation.
