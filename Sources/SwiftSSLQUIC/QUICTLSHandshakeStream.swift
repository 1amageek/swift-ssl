import SwiftSSLCore
import SwiftSSLTLS

/// A bounded QUIC-to-TLS message boundary for one encryption level.
public struct QUICTLSHandshakeStream:
    QUICTLSHandshakeStreaming,
    ~Copyable,
    Sendable
{
    private var reassembler: QUICCryptoStreamReassembler
    private let framer: TLS13HandshakeMessageFramer

    public static func make(
        encryptionLevel: QUICHandshakeEncryptionLevel,
        maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
        maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
    ) throws(QUICTLSHandshakeStreamError) -> Self {
        let framer = try Self.makeFramer(
            maximumMessageByteCount: maximumMessageByteCount
        )
        guard maximumBufferedByteCount > 0,
              maximumBufferedByteCount <= QUICCryptoStreamReassembler.maximumPermittedBufferByteCount else {
            throw .reassembly(.invalidBufferLimit(maximumBufferedByteCount))
        }
        guard framer.maximumMessageByteCount <= maximumBufferedByteCount else {
            throw .incompatibleLimits(
                maximumBufferedByteCount: maximumBufferedByteCount,
                maximumMessageByteCount: framer.maximumMessageByteCount
            )
        }
        let reassembler = try Self.makeReassembler(
            encryptionLevel: encryptionLevel,
            maximumBufferedByteCount: maximumBufferedByteCount
        )
        return Self(
            reassembler: consume reassembler,
            framer: framer
        )
    }

    private init(
        reassembler: consuming QUICCryptoStreamReassembler,
        framer: TLS13HandshakeMessageFramer
    ) {
        self.reassembler = reassembler
        self.framer = framer
    }

    public var encryptionLevel: QUICHandshakeEncryptionLevel {
        reassembler.encryptionLevel
    }

    public var nextReadOffset: UInt64 { reassembler.nextReadOffset }

    public var contiguousByteCount: Int { reassembler.contiguousByteCount }

    public var bufferedByteCount: Int { reassembler.bufferedByteCount }

    public mutating func receive(
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICTLSHandshakeStreamError) {
        do {
            try reassembler.receive(offset: offset, bytes: bytes)
        } catch {
            throw .reassembly(error)
        }
    }

    public borrowing func nextMessageStatus(
    ) throws(QUICTLSHandshakeStreamError) -> TLSHandshakeMessageFrameStatus {
        try reassembler.withContiguousBytes { bytes throws(QUICTLSHandshakeStreamError) in
            switch framer.frameStatus(for: bytes) {
            case .success(let status):
                return status
            case .failure(let error):
                throw .framing(error)
            }
        }
    }

    /// Borrows the first complete message without advancing the stream.
    ///
    /// A throwing consumer can return a `Result`; the caller then discards the
    /// message only after it has accepted the result.
    public borrowing func withNextMessage<Result>(
        _ body: (Span<UInt8>) -> Result
    ) throws(QUICTLSHandshakeStreamError) -> Result? {
        try reassembler.withContiguousBytes { bytes throws(QUICTLSHandshakeStreamError) in
            let status: TLSHandshakeMessageFrameStatus
            switch framer.frameStatus(for: bytes) {
            case .success(let value):
                status = value
            case .failure(let error):
                throw .framing(error)
            }
            switch status {
            case .needsMoreData:
                return nil
            case .complete(let messageByteCount):
                return body(bytes.extracting(0..<messageByteCount))
            }
        }
    }

    public mutating func discardNextMessage() throws(QUICTLSHandshakeStreamError) {
        let status = try nextMessageStatus()
        switch status {
        case .needsMoreData(let minimumAdditionalByteCount):
            throw .incompleteMessage(
                minimumAdditionalByteCount: minimumAdditionalByteCount
            )
        case .complete(let messageByteCount):
            do {
                try reassembler.discardContiguousBytes(count: messageByteCount)
            } catch {
                throw .reassembly(error)
            }
        }
    }

    private static func makeFramer(
        maximumMessageByteCount: Int
    ) throws(QUICTLSHandshakeStreamError) -> TLS13HandshakeMessageFramer {
        do {
            return try TLS13HandshakeMessageFramer(
                maximumMessageByteCount: maximumMessageByteCount
            )
        } catch {
            throw .framing(error)
        }
    }

    private static func makeReassembler(
        encryptionLevel: QUICHandshakeEncryptionLevel,
        maximumBufferedByteCount: Int
    ) throws(QUICTLSHandshakeStreamError) -> QUICCryptoStreamReassembler {
        do {
            return try QUICCryptoStreamReassembler(
                encryptionLevel: encryptionLevel,
                maximumBufferedByteCount: maximumBufferedByteCount
            )
        } catch {
            throw .reassembly(error)
        }
    }
}
