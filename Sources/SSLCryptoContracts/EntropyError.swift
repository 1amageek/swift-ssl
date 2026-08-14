public enum EntropyError: Error, Sendable, Equatable {
    case unavailable
    case requestTooLarge(limit: Int, requested: Int)
    case partialFill(expected: Int, actual: Int)
    case healthTestFailed
    case sourceRejected
    case backendFailure(code: Int)
    case unsupportedPlatform
}
