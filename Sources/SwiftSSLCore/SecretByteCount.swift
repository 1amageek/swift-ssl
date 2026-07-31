public struct SecretByteCount: Sendable, Hashable {
    public static let maximumSupportedByteCount = 1_048_576

    public let value: Int

    public init(_ value: Int) throws(SecretMemoryError) {
        guard value > 0 else {
            throw .invalidByteCount(value)
        }
        guard value <= Self.maximumSupportedByteCount else {
            throw .byteCountExceedsLimit(
                limit: Self.maximumSupportedByteCount,
                actual: value
            )
        }
        self.value = value
    }
}
