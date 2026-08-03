import SSLCore

/// Record-independent client-side TLS 1.3 handshake state transitions.
public protocol TLS13ClientHandshakeCoreProtocol:
    TLS13ApplicationTrafficSecretManaging,
    ~Copyable,
    Sendable
{
    var isEstablished: Bool { get }
    var earlyDataState: TLS13EarlyDataState { get }
    var earlyDataByteLimit: UInt32 { get }

    mutating func configureCertificateCompression(
        _ configuration: TLS13CertificateCompressionConfiguration
    ) throws(TLS13HandshakeEngineError)

    mutating func start()
        throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

    mutating func receiveHandshakeMessage(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput

    mutating func receiveHandshakeMessageStep(
        _ message: Span<UInt8>,
        at epoch: TLS13HandshakeEpoch
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition

    mutating func receivePostHandshakeAuthenticationRequestStep(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition

    mutating func resume(
        _ response: TLS13CapabilityResponse
    ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition

    mutating func makeResumptionState(
        ticket: TLS13NewSessionTicket,
        receivedAt: VerificationInstant
    ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState
}
