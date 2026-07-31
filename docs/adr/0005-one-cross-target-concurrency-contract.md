# ADR 0005: Keep one cross-target concurrency contract

- Status: Accepted
- Date: 2026-07-31

## Context

Embedded compilation mode does not imply a single-threaded runtime. WASI and Embedded platform implementations may provide threads, task concurrency, atomics, and mutexes. Removing synchronization under a feature flag changes correctness and `Sendable` semantics.

## Decision

Task/thread-reachable shared mutable state uses the same `Synchronization.Mutex<State>` or actor contract on Native, WASI, and Embedded targets.

Target conditionals may select platform implementations for entropy, clocks, persistence, and runtime hooks. They may not alter stored-state ownership, isolation, `Sendable` conformance, mutation entry points, shutdown, or release behavior.

Connection state remains single-owner and does not become globally shared. ISR/DMA boundaries use a dedicated target-specific queue or atomic handoff; task/thread processing returns to the common mutex/actor contract.

## Consequences

- The same logical state has the same race-safety proof on each target.
- A single-threaded deployment optimizes inside its platform mutex implementation, not by forking framework source.
- Target validation must include compile, link, and executable contention/failure tests where possible.
- `@unchecked Sendable` is permitted only for a documented immutable or uniquely owned pointer type whose lifetime and synchronization are independently verified.
