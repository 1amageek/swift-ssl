import SSLCore

/// Locates the first complete TLS handshake message in borrowed stream bytes.
public protocol TLSHandshakeMessageFraming: Sendable {
    associatedtype FramingError: Error

    var maximumMessageByteCount: Int { get }

    func frameStatus(
        for bytes: Span<UInt8>
    ) -> Result<TLSHandshakeMessageFrameStatus, FramingError>
}
