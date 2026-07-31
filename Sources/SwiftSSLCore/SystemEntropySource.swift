/// Cryptographically strong entropy supplied by the target's standard library runtime.
///
/// The runtime selects the operating-system or platform entropy backend. The source
/// owns no state and only borrows the caller's destination for the duration of `fill`.
public struct SystemEntropySource: EntropySource, Sendable {
    public static let maximumRequestByteCount = 1 << 20

    public init() {}

    public func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
        guard destination.count <= Self.maximumRequestByteCount else {
            throw .requestTooLarge(
                limit: Self.maximumRequestByteCount,
                requested: destination.count
            )
        }

        var generator = SystemRandomNumberGenerator()
        var index = 0
        while index < destination.count {
            var word = generator.next()
            let remaining = destination.count - index
            let count = Swift.min(remaining, MemoryLayout<UInt64>.size)
            var byte = 0
            while byte < count {
                destination[index + byte] = UInt8(truncatingIfNeeded: word)
                word >>= 8
                byte += 1
            }
            index += count
        }
    }
}
