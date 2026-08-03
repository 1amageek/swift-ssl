public enum SecretMemoryError: Error, Sendable, Equatable {
    case invalidByteCount(Int)
    case byteCountExceedsLimit(limit: Int, actual: Int)
}
