import SSLCore

/// Stateless TLS 1.3 handshake framing over a borrowed ordered byte stream.
public struct TLS13HandshakeMessageFramer: TLSHandshakeMessageFraming, Sendable {
    public typealias FramingError = TLSHandshakeMessageFramingError

    public static let headerByteCount = 4
    public static let defaultMaximumMessageByteCount = 1 * 1024 * 1024
    public static let protocolMaximumMessageByteCount = 0x00FF_FFFF + headerByteCount

    public let maximumMessageByteCount: Int

    public init(
        maximumMessageByteCount: Int = Self.defaultMaximumMessageByteCount
    ) throws(TLSHandshakeMessageFramingError) {
        guard maximumMessageByteCount >= Self.headerByteCount,
              maximumMessageByteCount <= Self.protocolMaximumMessageByteCount else {
            throw .invalidMaximumMessageByteCount(maximumMessageByteCount)
        }
        self.maximumMessageByteCount = maximumMessageByteCount
    }

    public func status(
        for bytes: Span<UInt8>
    ) throws(TLSHandshakeMessageFramingError) -> TLSHandshakeMessageFrameStatus {
        guard bytes.count >= Self.headerByteCount else {
            return .needsMoreData(
                minimumAdditionalByteCount: Self.headerByteCount - bytes.count
            )
        }

        let bodyByteCount =
            (Int(bytes[1]) << 16) |
            (Int(bytes[2]) << 8) |
            Int(bytes[3])
        let messageByteCount = Self.headerByteCount + bodyByteCount
        guard messageByteCount <= maximumMessageByteCount else {
            throw .messageTooLarge(
                maximum: maximumMessageByteCount,
                actual: messageByteCount
            )
        }
        guard bytes.count >= messageByteCount else {
            return .needsMoreData(
                minimumAdditionalByteCount: messageByteCount - bytes.count
            )
        }
        return .complete(messageByteCount: messageByteCount)
    }

    public func frameStatus(
        for bytes: Span<UInt8>
    ) -> Result<TLSHandshakeMessageFrameStatus, TLSHandshakeMessageFramingError> {
        do {
            return .success(try status(for: bytes))
        } catch {
            return .failure(error)
        }
    }
}
