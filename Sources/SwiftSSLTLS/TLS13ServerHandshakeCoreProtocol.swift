import SwiftSSLCore

/// Record-independent server-side TLS 1.3 handshake state transitions.
public protocol TLS13ServerHandshakeCoreProtocol:
  TLS13ApplicationTrafficSecretManaging,
  ~Copyable,
  Sendable
{
  var isEstablished: Bool { get }
  var authenticatedClientIdentity: TLS13ValidatedClientCertificate? { get }
  var earlyDataState: TLS13EarlyDataState { get }
  var earlyDataByteLimit: UInt32 { get }

  mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(TLS13HandshakeEngineError)

    mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

    mutating func receiveHandshakeMessageStep(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition

  mutating func requestPostHandshakeClientAuthentication(
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

    mutating func resume(
        _ response: TLS13CapabilityResponse
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition

  mutating func makeResumptionState(
    ticket: Span<UInt8>,
    ticketNonce: Span<UInt8>,
    issuedAt: VerificationInstant,
    lifetime: UInt32,
    ageAdd: UInt32,
    maximumEarlyDataByteCount: UInt32
  ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState
}
