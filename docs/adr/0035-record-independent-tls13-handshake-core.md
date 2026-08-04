# ADR 0035: Separate TLS 1.3 semantics from record and QUIC transport

## Status

Accepted.

## Context

The original synchronous TLS 1.3 engine consumed complete TLS records. QUIC
does not use the TLS record layer: CRYPTO frames carry TLS handshake messages
at encryption levels owned by QUIC. Reusing the record engine would introduce
synthetic record headers, duplicate AEAD work, and the wrong ownership model.

The `swift-quic` adapter owns bounded offset reassembly and complete-message
framing. It needs a transport-neutral state machine that owns only the
TLS transcript, authentication decisions, Finished verification, resumption,
and key schedule.

## Decision

`TLS13ClientHandshakeCore` and `TLS13ServerHandshakeCore` consume one complete
handshake message plus an explicit TLS epoch. They implement narrow public
protocols and emit `TLS13HandshakeCoreOutput` values containing:

- one owned byte backing with checked ranges for outbound handshake messages;
- ordered semantic actions;
- noncopyable client/server traffic-secret pairs at handshake and application
  epochs; and
- explicit completion and confirmation transitions.

The core never frames, seals, opens, retransmits, or reassembles bytes.

`QUICTLSClientHandshake` and `QUICTLSServerHandshake` compose the core and
consume one complete, header-inclusive message per call. The transport owns
the reassembly buffer and keeps the borrow valid for the call. The adapter maps
client/server secret names to local read/write directions and preserves effect
order.

`TLS13ClientHandshake` and `TLS13ServerHandshake` are Stream record adapters
over the same core. They parse inbound record boundaries as checked ranges,
open authenticated handshake records, and pass borrowed complete messages to
the core. Outbound handshake messages are sealed directly into the final
record-batch backing. Application records, NewSessionTicket transport, and
KeyUpdate record transitions remain Stream-adapter responsibilities.

Traffic secrets are copied once when exported from the key schedule because
the state machine must retain its own secret owner while the transport takes
an independently wiped owner. Message bytes are not materialized between the
reassembly buffer and the semantic core. Outbound action ranges share one
owned backing.

## Consequences

- QUIC does not depend on TLS record protection.
- Full and PSK-resumed handshakes use the same semantic path.
- Conflicting CRYPTO retransmissions fail before TLS state changes.
- Secret direction and delivery order are explicit, typed effects.
- Stream TLS and QUIC now share one semantic implementation; transport
  adapters cannot independently change transcript or authentication state.
- QUIC transport parameters, ALPN policy, and post-handshake application-epoch
  processing remain separate responsibilities and are not hidden fallbacks.

## Verification

- deterministic record-independent client/server completion;
- matching client/server handshake and application secrets;
- PSK resumption without Certificate or CertificateVerify;
- tampered ServerFinished rejection;
- wrong-epoch rejection followed by failed-state rejection;
- out-of-order CRYPTO delivery through reassembly and framing;
- conflicting overlap rejection before TLS message consumption; and
- three repeated focused Native runs and focused AddressSanitizer execution;
- full-handshake execution with directional-secret comparison on Native,
  WASI, and Embedded WASI using the pinned Swift 6.4 snapshot; and
- Stream full/resumed handshakes, all cipher suites, application records,
  encrypted tickets, KeyUpdate request/response, Ed25519 and P-256/P-384/P-521
  CertificateVerify, tamper rejection, and focused AddressSanitizer execution;
- allocation, fuzzing, and external interoperability gates as recorded in the
  verification ledger.
