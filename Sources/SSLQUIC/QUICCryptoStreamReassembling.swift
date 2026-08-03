import SSLCore

/// Ordered, bounded ownership boundary for one QUIC CRYPTO offset space.
public protocol QUICCryptoStreamReassembling: ~Copyable, Sendable {
    var encryptionLevel: QUICHandshakeEncryptionLevel { get }
    var maximumBufferedByteCount: Int { get }
    var nextReadOffset: UInt64 { get }
    var contiguousByteCount: Int { get }
    var bufferedByteCount: Int { get }

    mutating func receive(
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICCryptoStreamError)

    borrowing func withContiguousBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result

    mutating func discardContiguousBytes(
        count: Int
    ) throws(QUICCryptoStreamError)
}
