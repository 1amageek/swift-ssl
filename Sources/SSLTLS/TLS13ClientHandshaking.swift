import SSLCore

/// Stream TLS 1.3 client operations over caller-owned transport I/O.
public protocol TLS13ClientHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }
    var negotiatedApplicationProtocol: TLS13ApplicationProtocol? { get }
    var receivedTransportParameters: OwnedBytes? { get }
    var earlyDataState: TLS13EarlyDataState { get }
    var earlyDataByteLimit: UInt32 { get }

    mutating func configureCertificateCompression(
        _ configuration: TLS13CertificateCompressionConfiguration
    ) throws(TLS13HandshakeEngineError)
    mutating func start() throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receive(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receiveRecordStep(_ record: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
    mutating func resume(_ response: TLS13CapabilityResponse)
        throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
    mutating func sendEarlyData(_ content: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func sendApplicationData(_ content: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receiveApplicationRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> OwnedBytes
    mutating func receiveNewSessionTicket(
        _ input: Span<UInt8>,
        receivedAt: VerificationInstant
    ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState
    mutating func requestKeyUpdate(requestPeerUpdate: Bool)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receivePostHandshakeRecord(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
    mutating func receivePostHandshakeRecordStep(_ input: Span<UInt8>)
        throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition
}
