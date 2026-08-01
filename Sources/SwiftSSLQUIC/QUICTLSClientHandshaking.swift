import SwiftSSLCore

public protocol QUICTLSClientHandshaking: ~Copyable, Sendable {
    var isEstablished: Bool { get }

    mutating func start() throws(QUICTLSHandshakeError) -> QUICTLSStepOutput

    mutating func receiveCrypto(
        level: QUICTLSHandshakeInputLevel,
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeError)

    mutating func processNextMessage(
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput?
}
