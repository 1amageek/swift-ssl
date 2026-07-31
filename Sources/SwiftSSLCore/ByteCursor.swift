public struct ByteCursor: ~Escapable {
    private let bytes: Span<UInt8>
    public private(set) var offset: Int

    @_lifetime(copy bytes)
    public init(_ bytes: Span<UInt8>) {
        self.bytes = bytes
        offset = 0
    }

    public var count: Int {
        bytes.count
    }

    public var remainingCount: Int {
        bytes.count - offset
    }

    public var isAtEnd: Bool {
        offset == bytes.count
    }

    public var remainingSpan: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get {
            bytes.extracting(droppingFirst: offset)
        }
    }

    public mutating func readByte() throws(ByteError) -> UInt8 {
        guard offset < bytes.count else {
            throw .outOfBounds(offset: offset, requested: 1, available: 0)
        }

        let byte = bytes[offset]
        offset += 1
        return byte
    }

    @_lifetime(copy self)
    public mutating func readSpan(count: Int) throws(ByteError) -> Span<UInt8> {
        guard count >= 0 else {
            throw .negativeCount(count)
        }

        let (endOffset, overflow) = offset.addingReportingOverflow(count)
        guard !overflow else {
            throw .offsetOverflow(offset: offset, count: count)
        }
        guard endOffset <= bytes.count else {
            throw .outOfBounds(
                offset: offset,
                requested: count,
                available: remainingCount
            )
        }

        let result = bytes.extracting(offset..<endOffset)
        offset = endOffset
        return result
    }

    public mutating func skip(count: Int) throws(ByteError) {
        _ = try readSpan(count: count)
    }

    public mutating func readUInt16BigEndian() throws(ByteError) -> UInt16 {
        let value = try readSpan(count: 2)
        return (UInt16(value[0]) << 8) | UInt16(value[1])
    }

    public mutating func readUInt24BigEndian() throws(ByteError) -> UInt32 {
        let value = try readSpan(count: 3)
        return
            (UInt32(value[0]) << 16)
            | (UInt32(value[1]) << 8)
            | UInt32(value[2])
    }

    public mutating func readUInt32BigEndian() throws(ByteError) -> UInt32 {
        let value = try readSpan(count: 4)
        return
            (UInt32(value[0]) << 24)
            | (UInt32(value[1]) << 16)
            | (UInt32(value[2]) << 8)
            | UInt32(value[3])
    }

    public func requireFullyConsumed() throws(ByteError) {
        guard isAtEnd else {
            throw .trailingBytes(count: remainingCount)
        }
    }
}
