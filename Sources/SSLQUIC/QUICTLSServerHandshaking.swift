import SSLCore
import SSLTLS

public protocol QUICTLSServerHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }
    var negotiatedApplicationProtocol: TLS13ApplicationProtocol? { get }
    var receivedTransportParameters: OwnedBytes? { get }
    var authenticatedClientIdentity: TLS13ValidatedClientCertificate? { get }
    var earlyDataState: TLS13EarlyDataState { get }
    var earlyDataByteLimit: UInt32 { get }

    mutating func configureCertificateCompression(
        _ configuration: TLS13CertificateCompressionConfiguration
    ) throws(QUICTLSHandshakeError)

    mutating func receiveCrypto(
        level: QUICTLSHandshakeInputLevel,
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeError)

    mutating func processNextMessage(
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput?

    mutating func processNextMessageStep(
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition?

    mutating func resume(
        _ response: TLS13CapabilityResponse
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition

    mutating func updateOneRTTTrafficSecret(
        for direction: QUICSecretDirection
    ) throws(QUICTLSHandshakeError) -> QUICTrafficSecretEvent
}
