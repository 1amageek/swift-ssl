public enum TLSHandshakeMessageFramingError: Error, Sendable, Equatable {
    case invalidMaximumMessageByteCount(Int)
    case messageTooLarge(maximum: Int, actual: Int)
}
