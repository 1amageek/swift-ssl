public enum TLSHandshakeMessageFrameStatus: Sendable, Equatable {
    /// The exact minimum additional bytes needed to complete the header or body.
    case needsMoreData(minimumAdditionalByteCount: Int)

    /// The byte count of the first complete message, including its header.
    case complete(messageByteCount: Int)
}
