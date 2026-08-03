public struct OwnedBytes: Sendable, Equatable, Hashable {
    private let storage: ContiguousArray<UInt8>

    public init() {
        storage = []
    }

    public init(consuming storage: consuming ContiguousArray<UInt8>) {
        self.storage = storage
    }

    public init(copying bytes: Span<UInt8>) {
        var storage = ContiguousArray<UInt8>()
        storage.reserveCapacity(bytes.count)

        var index = 0
        while index < bytes.count {
            storage.append(bytes[index])
            index += 1
        }

        self.storage = storage
    }

    public var count: Int {
        storage.count
    }

    public var isEmpty: Bool {
        storage.isEmpty
    }

    public var span: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get {
            storage.span
        }
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(storage.span)
    }

    public subscript(index: Int) -> UInt8 {
        storage[index]
    }

    public func contains(_ range: ByteRange) -> Bool {
        range.endOffset <= storage.count
    }

    @_lifetime(borrow self)
    public func span(in range: ByteRange) throws(ByteError) -> Span<UInt8> {
        guard contains(range) else {
            throw .outOfBounds(
                offset: range.offset,
                requested: range.count,
                available: Swift.max(0, storage.count - range.offset)
            )
        }
        return storage.span.extracting(range.offset..<range.endOffset)
    }
}
