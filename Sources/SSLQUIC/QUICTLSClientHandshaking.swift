import SSLCore
import SSLTLS

public protocol QUICTLSClientHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }
    var negotiatedApplicationProtocol: TLS13ApplicationProtocol? { get }
    var receivedTransportParameters: OwnedBytes? { get }
    var earlyDataState: TLS13EarlyDataState { get }
    var earlyDataByteLimit: UInt32 { get }

    mutating func configureCertificateCompression(
        _ configuration: TLS13CertificateCompressionConfiguration
    ) throws(QUICTLSHandshakeError)

    mutating func start() throws(QUICTLSHandshakeError) -> QUICTLSStepOutput

    mutating func processHandshakeMessage(
        _ message: Span<UInt8>,
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput

    mutating func processHandshakeMessageStep(
        _ message: Span<UInt8>,
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition

    mutating func resume(
        _ response: TLS13CapabilityResponse
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition

    mutating func updateOneRTTTrafficSecret(
        for direction: QUICSecretDirection
    ) throws(QUICTLSHandshakeError) -> QUICTrafficSecretEvent
}
