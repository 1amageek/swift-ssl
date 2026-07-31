public enum AEADError: Error, Sendable, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidNonceLength(expected: Int, actual: Int)
    case outputTooSmall(required: Int, actual: Int)
    case authenticationFailed
    case messageLimitReached
}
