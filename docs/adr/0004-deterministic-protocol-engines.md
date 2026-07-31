# ADR 0004: Use deterministic protocol engines with explicit effects

- Status: Accepted
- Date: 2026-07-31

## Context

Callback-driven TLS APIs mix protocol progress, transport readiness, private-key operations, trust evaluation, and session storage. Reentrancy and integer WANT states make failure and suspension hard to model. They are also poor fits for Embedded systems and for independent state-machine testing.

## Decision

TLS 1.3 and DTLS 1.3 connections are single-owner mutable values. Synchronous step methods consume borrowed input or a typed event and return an owned action batch.

Potentially asynchronous work is represented by a correlated capability request. The engine records one typed suspension point and resumes only with a matching response. Stale, duplicated, wrong-kind, and wrong-state responses fail explicitly.

Stream TLS, DTLS, and QUIC integration share the handshake core but use sealed profiles for legal framing, message, timer, and secret-delivery behavior.

## Consequences

- State transitions are deterministic and can be exhaustively tested with no I/O.
- Applications may drive the same engine from async/await, a poll loop, an RTOS task, or an interrupt-fed queue without changing semantics.
- Async provider protocols live in driver code; the engine itself never awaits or invokes reentrant callbacks.
- Early data, established sessions, and ECH retry outcomes are different states/types.
- Output bytes and side effects are visible and auditable.
