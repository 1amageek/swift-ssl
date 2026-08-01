# ADR 0034: Separate QUIC reassembly from TLS handshake framing

## Status

Accepted.

## Context

QUIC delivers TLS handshake bytes without TLS records. CRYPTO reassembly owns
offset ordering and buffering, but it must not also own the TLS handshake
header format or advance the TLS state machine. The adapter needs to expose one
complete borrowed message at a time, preserve incomplete data, and reject a
declared message larger than policy before waiting for attacker-controlled
input.

The pinned Swift 6.4 WASI runtime trapped while instantiating metadata for an
initial generic `QUICTLSHandshakeStream<Framer>` implementation. Native tests
and WASI compile/link had succeeded; only WASI execution exposed the failure.
The public execution path therefore cannot depend on that generic metadata
shape for this baseline.

## Decision

`TLSHandshakeMessageFraming` defines the framing responsibility independently
of storage. Its associated failure remains typed in a `Result` because the
pinned compiler erases a generic protocol call's typed `catch` to `any Error`.
`TLS13HandshakeMessageFramer` provides both that protocol result and a concrete
typed-throws convenience. It reads only the four-byte handshake header and
returns either the exact first-message byte count or the exact minimum bytes
still needed.

`QUICTLSHandshakeStreaming` defines the QUIC-facing receive, status, scoped
message borrow, and explicit discard operations. `QUICTLSHandshakeStream`
implements the protocol by composing one `QUICCryptoStreamReassembler` with
one concrete `TLS13HandshakeMessageFramer`. Failed construction uses a static
factory so the noncopyable reassembly owner is initialized and consumed exactly
once on Swift 6.4.

Message borrowing does not advance the stream. The consumer calls
`discardNextMessage` only after accepting the result. A consumer operation that
can fail can return a `Result` from the nonthrowing borrow closure, inspect it,
and leave the message buffered when retry or error handling requires that.

No unsafe pointer is used. The reassembler's mirrored contiguous owner and the
framer's range calculation already provide a scoped zero-copy `Span`; unsafe
memory access would not remove the one required input ownership copy.

## Design alignment

| Concern | Existing library invariant | Decision | Classification |
|---|---|---|---|
| Public API | Small protocols with separate implementations | Framing, reassembly, and composed stream protocols remain distinct | Aligned |
| Errors | Typed failure without fallback | Framing, reassembly, configuration, and incomplete input remain distinguishable | Aligned |
| Ownership | Owned backing plus scoped borrow | Noncopyable ring owner and closure-bound message `Span` | Aligned |
| Concurrency | No unprotected shared mutable state | Sendable value with exclusive mutating entry points | Aligned |
| Lifetime | Borrow cannot outlive owner | Message pointer never escapes the borrow closure | Aligned |
| Compatibility | Modern profile without C API emulation | TLS 1.3 handshake header only | Aligned |
| Performance | Explicit input ownership and zero-copy output paths | One input copy, zero framing/output copies | Aligned |
| Platform capability | One semantic source across targets | Concrete composition avoids the observed WASI generic metadata trap | Compatible |
| Testing | Success and typed failure behavior on real paths | Native focused tests plus three-target runtime command | Aligned |

## Responsibility map

| Component | Owns | Does not own |
|---|---|---|
| `QUICCryptoStreamReassembler` | Offset ordering, bounded storage, overlap policy | TLS message syntax, TLS state |
| `TLSHandshakeMessageFraming` | Handshake header boundary and size policy | Byte ownership, stream offsets, TLS state |
| `QUICTLSHandshakeStream` | Composition and accepted-message advancement | TLS semantic parsing, handshake transitions, packet protection |
| Future QUIC TLS engine adapter | TLS state transitions and ordered effects | QUIC packets, congestion control, socket I/O |

## Target ownership matrix

| Target | Storage | Isolation | Read | Mutation | Release |
|---|---|---|---|---|---|
| Native | Noncopyable stream owning the ring | Exclusive value mutation | Scoped message `Span` | `receive`, `discardNextMessage` | Owner releases arrays |
| WASI | Same | Same | Same | Same | Same |
| Embedded WASI | Same | Same | Same | Same | Same |

## Verification

Native tests cover header/body fragmentation, exact minimum byte reporting,
multiple messages, out-of-order CRYPTO input, ring wrap, incompatible limits,
typed framing/reassembly failures, and explicit incomplete discard failure.
The adapter suite runs three times through the hang guard. A dedicated command
executes reassembly, wrap, framing, borrowing, discard, and conflicting overlap
on Native, WASI, and Embedded WASI from the same source. The focused adapter
suite also completes under AddressSanitizer without a runtime diagnostic.
