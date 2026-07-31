public struct SecretBytes: ~Copyable {
    private let pointer: UnsafeMutablePointer<UInt8>
    public let count: Int

    // Unsafe boundary invariants:
    // - This value is the unique owner of an allocation containing count UInt8 values.
    // - The allocation is initialized to zero before user initialization begins.
    // - The initialization closure receives a scoped mutable span and cannot retain it.
    // - The pointer never leaves this type; public access is a scoped immutable span borrow.
    // - UInt8 has stride and alignment one, and SecretByteCount has validated a positive count.
    // - No bind, rebind, or overlapping alias is created.
    // - Failure erases, deinitializes, and deallocates the local allocation before rethrowing.
    // - Success transfers exactly-once erase and deallocation responsibility to deinit.
    public init<Failure: Error>(
        byteCount: SecretByteCount,
        initializingWith initializer: (inout MutableSpan<UInt8>) throws(Failure) -> Void
    ) throws(Failure) {
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: byteCount.value)
        pointer.initialize(repeating: 0, count: byteCount.value)

        do {
            var span = MutableSpan(_unsafeStart: pointer, count: byteCount.value)
            try initializer(&span)
        } catch {
            SecureWipe.erase(
                UnsafeMutableRawPointer(pointer),
                byteCount: byteCount.value
            )
            pointer.deinitialize(count: byteCount.value)
            pointer.deallocate()
            throw error
        }

        self.pointer = pointer
        count = byteCount.value
    }

    public init(copying bytes: Span<UInt8>) throws(SecretMemoryError) {
        let byteCount = try SecretByteCount(bytes.count)
        self.init(byteCount: byteCount) { destination in
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }

    public borrowing func withBorrowedBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let buffer = UnsafeBufferPointer(start: pointer, count: count)
        let span = Span(_unsafeElements: buffer)
        return try body(span)
    }

    // Unsafe boundary invariants:
    // - This value remains the unique owner for the entire mutable borrow.
    // - The initialized UInt8 allocation is exposed only through MutableSpan.
    // - The caller cannot retain the span or its derived pointer beyond this call.
    // - No type rebinding, aliasing, or Sendable crossing occurs while mutating.
    public mutating func withMutableBorrowedBytes<Result, Failure: Error>(
        _ body: (inout MutableSpan<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        var span = MutableSpan(_unsafeStart: pointer, count: count)
        return try body(&span)
    }

    deinit {
        SecureWipe.erase(UnsafeMutableRawPointer(pointer), byteCount: count)
        pointer.deinitialize(count: count)
        pointer.deallocate()
    }
}

// SecretBytes is uniquely owned and noncopyable. Its only public data access is an
// immutable scoped borrow, and destruction cannot race with a live borrow.
extension SecretBytes: @unchecked Sendable {}
