import SwiftSSLCore

/// Record-independent server-side TLS 1.3 handshake state transitions.
public protocol TLS13ServerHandshakeCoreProtocol:
  TLS13ApplicationTrafficSecretManaging,
  ~Copyable,
  Sendable
{
  var isEstablished: Bool { get }

  mutating func receiveHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

  mutating func makeResumptionState(
    ticket: Span<UInt8>,
    ticketNonce: Span<UInt8>,
    issuedAt: VerificationInstant,
    lifetime: UInt32,
    ageAdd: UInt32
  ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState
}
