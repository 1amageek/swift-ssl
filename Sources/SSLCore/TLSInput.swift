/// An owned input buffer for a TLS session boundary.
///
/// Parsing APIs borrow the bytes through `withBorrowedBytes`; the borrow cannot
/// escape the closure, so a parser never stores a pointer into transport memory.
public struct TLSInput: Sendable, Equatable, Hashable {
    private let storage: OwnedBytes

    public init(copying bytes: Span<UInt8>) {
        storage = OwnedBytes(copying: bytes)
    }

    public init(consuming storage: OwnedBytes) {
        self.storage = consume storage
    }

    public var count: Int { storage.count }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes(body)
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        in range: TLSBufferRange,
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws -> Result {
        let bytes = try storage.span(in: ByteRange(offset: range.offset, count: range.count))
        return try body(bytes)
    }
}
