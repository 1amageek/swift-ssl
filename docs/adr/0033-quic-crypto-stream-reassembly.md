# ADR 0033: Bound QUIC CRYPTO stream reassembly per encryption level

## Status

Accepted.

## Context

QUIC carries TLS handshake bytes in an ordered CRYPTO stream with independent
offset spaces for the Initial, Handshake, and 1-RTT encryption levels. Frames
can arrive out of order and can repeat or overlap previously received bytes.
The TLS consumer needs one contiguous borrowed prefix, while an unbounded
reassembly map would permit attacker-controlled memory growth.

The public API must preserve the existing SwiftSSL ownership model: borrowed
input cannot outlive the call, output views cannot escape their owner, and
malformed or resource-exhausting input must produce a typed failure without
partial mutation. The same source and ownership contract must execute on
Native, WASI, and Embedded WASI.

## Decision

`QUICCryptoStreamReassembler` owns one explicitly identified encryption level.
It copies each newly accepted input byte once into a fixed-capacity sliding
ring and tracks occupancy with a bit set. Received bytes are also written into
a mirrored second half of the same contiguous allocation. This mirror permits
a wrapped ring prefix to be borrowed as one `Span<UInt8>` without allocating or
materializing an output buffer.

The receive operation validates every overlap before committing any new byte.
Equal retransmissions are accepted without changing the unique-byte count;
conflicting overlaps fail with `QUICCryptoStreamError.conflictingOverlap` and
leave the stream unchanged. QUIC offsets, the configured capacity, and discard
ranges are checked before mutation and have distinct typed failures.

The ring owner is a noncopyable `Sendable` value. It has no shared mutable
state and uses the same storage and mutation entry points on every target. No
unsafe pointer is used: `ContiguousArray` plus scoped `Span` borrowing already
meets the lifetime and output-copy budget, so an unsafe boundary would add risk
without removing a copy.

| Target | Storage owner | Isolation | Read entry point | Mutation entry points | Release |
|---|---|---|---|---|---|
| Native | Noncopyable reassembler value | Exclusive value mutation | Scoped `withContiguousBytes` borrow | `receive`, `discardContiguousBytes` | Value-owned arrays release with the owner |
| WASI | Same | Same | Same | Same | Same |
| Embedded WASI | Same | Same | Same | Same | Same |

## Consequences

- Input bytes require one ownership copy because frame storage is only borrowed.
- Contiguous TLS delivery requires zero output copies, including across wrap.
- Mirroring doubles the configured byte-storage allocation; the occupancy bit
  set adds one bit per logical slot.
- Memory use is fixed at initialization and attacker input cannot grow it.
- One instance represents one encryption level; callers cannot accidentally
  merge independent QUIC CRYPTO offset spaces.
- TLS handshake-message framing and engine integration remain separate work and
  are not implied by byte-stream reassembly.

## Verification

Native tests cover out-of-order delivery, retransmission, equal overlap, ring
reuse across wrap, transactional conflicting-overlap failure, protocol/window
limits, and invalid discard. The focused suite is run three times through the
hang guard. A dedicated executable runs the success, wrap, and conflict paths
from the same source on Native, WASI, and Embedded WASI using the pinned Swift
6.4 toolchain and matching SDKs.
