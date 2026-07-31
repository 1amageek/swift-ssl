# ADR 0008: Order QUIC TLS effects with a single transfer owner

- Status: Accepted
- Date: 2026-07-31

## Context

A QUIC TLS step can produce ordinary wire actions and traffic secrets in one semantic sequence. Returning an action batch and independent secret events loses their relative order. Storing both in a normal `ContiguousArray` is not possible because traffic-secret owners are noncopyable, and weakening the secret owner to make the array compile would violate its lifetime and wipe contract.

The package baseline includes macOS 15. `InlineArray` is therefore not available as a portable public storage solution even though the pinned development compiler can compile it for newer deployment targets.

## Decision

`QUICTLSStepOutput` is the one noncopyable transfer owner for a synchronous QUIC TLS step. It owns:

- one `QUICTLSActionBatch` containing ordinary bytes and copyable range actions;
- one copyable descriptor tape that declares the exact action/secret order;
- six fixed optional secret slots representing read/write × 0-RTT/Handshake/1-RTT;
- one cursor used by `nextEffect()` to transfer effects in order.

Secret material never enters the ordinary byte backing or a copyable collection. A secret descriptor consumes its matching slot and returns a noncopyable `QUICTrafficSecretEvent`. Wire bytes remain available only through a scoped borrow of the batch backing.

Construction is package-restricted. Secret insertion derives the fixed slot from the event's own direction and level, so a caller cannot place contradictory metadata in a named slot. Duplicate storage is a typed failure. Step-output construction then validates a bijection between descriptors and stored effects: action indices must be in range, and every action and populated secret slot must appear exactly once. Missing, duplicate, and out-of-range references are typed failures.

The validation deliberately uses no second scratch allocation. Its current quadratic scan is acceptable only for the small internally generated effect sets of one engine step; an explicit maximum-effect bound and measurement are required before the QUIC engine can be declared complete.

A capability request will be modeled as a terminal suspended step result rather than as an ordinary descriptor. The request token must contain engine identity, a monotonically increasing sequence, and capability kind. The future engine must reject no-pending, duplicate, stale, wrong-kind, and wrong-state responses with typed errors. No callable request placeholder is added before that engine state exists.

## Consequences

- Drivers observe action and traffic-secret effects in one unambiguous order.
- Each secret has one owner, one scoped read boundary, and at most one transfer.
- The ordinary output bytes retain one backing allocation and range-only actions.
- Native, WASI, and Embedded builds use the same source, storage layout contract, and `Sendable` contract.
- Capability suspension cannot be mistaken for a callback or for an effect followed by speculative engine progress.

## Verification

Nine focused Native tests cover declared order, exact-once exhaustion, all six metadata-derived secret slots, duplicate secret storage, out-of-range action indices, duplicate and unreferenced actions, missing secret storage, and duplicate and unreferenced secret descriptors. The target-validation executable constructs and consumes the same production path. It ran successfully on Native, WASI, and Embedded WASI with the pinned 2026-07-23 Swift 6.4 toolchain and matching SDKs.
