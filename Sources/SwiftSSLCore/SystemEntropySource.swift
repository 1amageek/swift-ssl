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

        let byteCount = destination.count
        guard byteCount > 0 else { return }

        #if hasFeature(Embedded)
        // The pinned Embedded static standard library exposes entropy through
        // SystemRandomNumberGenerator, but does not link its private C symbol
        // for a direct reference from another module. This public entry point
        // retains the same runtime entropy semantics and ownership contract.
        var generator = SystemRandomNumberGenerator()
        var index = 0
        while index < byteCount {
            var word = generator.next()
            let remaining = byteCount - index
            let count = Swift.min(remaining, MemoryLayout<UInt64>.size)
            var byte = 0
            while byte < count {
                destination[index + byte] = UInt8(truncatingIfNeeded: word)
                word >>= 8
                byte += 1
            }
            index += count
        }
        #else
        // Unsafe boundary invariants:
        // - The caller owns initialized UInt8 storage for exactly destination.count bytes.
        // - MutableSpan scopes the borrow and the pointer cannot escape this closure.
        // - UInt8 has stride and alignment one, so no rebinding or alignment adjustment occurs.
        // - The byte count is nonnegative and bounded above before entering this boundary.
        // - The runtime initializes the complete range synchronously; no shared state crosses it.
        destination.withUnsafeMutableBufferPointer { buffer in
            precondition(buffer.count == byteCount)
            swiftSSLRuntimeRandom(buffer.baseAddress!, byteCount)
        }
        #endif
    }
}

// SystemRandomNumberGenerator invokes this same Swift runtime entry point for
// each UInt64. Calling it once preserves the runtime-selected platform entropy
// backend while filling the caller's contiguous buffer without intermediate
// words or repeated boundary crossings.
#if !hasFeature(Embedded)
@_extern(c, "swift_stdlib_random")
private func swiftSSLRuntimeRandom(
    _ buffer: UnsafeMutableRawPointer,
    _ byteCount: Int
)
#endif
