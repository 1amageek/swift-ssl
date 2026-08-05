import SSLCore

/// Stream TLS 1.3 server operations over caller-owned transport I/O.
public protocol TLS13ServerHandshaking: ~Copyable, Sendable {
  var isEstablished: Bool { get }
  var negotiatedApplicationProtocol: TLS13ApplicationProtocol? { get }
  var receivedTransportParameters: OwnedBytes? { get }
  var authenticatedClientIdentity: TLS13ValidatedClientCertificate? { get }
  var earlyDataState: TLS13EarlyDataState { get }
  var earlyDataByteLimit: UInt32 { get }

  mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(TLS13HandshakeEngineError)
  mutating func receive(_ input: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  mutating func receiveRecordStep(_ record: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
  mutating func resume(_ response: TLS13CapabilityResponse)
    throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
  mutating func sendApplicationData(_ content: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  mutating func receiveApplicationRecord(_ input: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> OwnedBytes
  mutating func receiveApplicationRecordStep(_ input: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13StreamRecordTransition
  mutating func sendNewSessionTicket(
    lifetime: UInt32,
    ageAdd: UInt32,
    ticketNonce: Span<UInt8>,
    ticket: Span<UInt8>,
    issuedAt: VerificationInstant,
    maximumEarlyDataByteCount: UInt32,
    extensions: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13IssuedSessionTicket
  mutating func requestKeyUpdate(requestPeerUpdate: Bool)
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  mutating func requestPostHandshakeClientAuthentication(
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  mutating func receivePostHandshakeRecord(_ input: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  mutating func receivePostHandshakeRecordStep(_ input: Span<UInt8>)
    throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
}
