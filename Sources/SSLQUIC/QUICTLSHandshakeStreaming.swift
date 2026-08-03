import SSLCore
import SSLTLS

/// Converts offset-addressed QUIC CRYPTO frames into borrowed TLS messages.
public protocol QUICTLSHandshakeStreaming: ~Copyable, Sendable {
    var encryptionLevel: QUICHandshakeEncryptionLevel { get }
    var nextReadOffset: UInt64 { get }
    var contiguousByteCount: Int { get }
    var bufferedByteCount: Int { get }

    mutating func receive(
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeStreamError)

    borrowing func nextMessageStatus(
    ) throws(QUICTLSHandshakeStreamError) -> TLSHandshakeMessageFrameStatus

    borrowing func withNextMessage<Result: ~Copyable>(
        _ body: (Span<UInt8>) -> Result
    ) throws(QUICTLSHandshakeStreamError) -> Result?

    mutating func discardNextMessage() throws(QUICTLSHandshakeStreamError)
}
