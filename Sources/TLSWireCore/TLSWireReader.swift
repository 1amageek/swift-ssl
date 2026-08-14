import NetworkingCore

/// A TLS wire cursor borrowing caller-owned contiguous storage.
public struct TLSWireReader: ~Escapable {
    private var cursor: ByteCursor

    @_lifetime(copy bytes)
    public init(_ bytes: Span<UInt8>) {
        cursor = ByteCursor(bytes)
    }

    @_lifetime(borrow bytes)
    public init(_ bytes: borrowing [UInt8]) {
        cursor = ByteCursor(bytes.span)
    }

    public var count: Int { cursor.count }
    public var position: Int { cursor.offset }
    public var remaining: Int { cursor.remainingCount }
    public var isAtEnd: Bool { cursor.isAtEnd }

    public var remainingSpan: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { cursor.remainingSpan }
    }

    public mutating func skip(_ count: Int) throws(ByteError) {
        try cursor.skip(count: count)
    }

    public mutating func readBytes(_ count: Int) throws(ByteError) -> [UInt8] {
        let bytes = try cursor.readSpan(count: count)
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        bytes.bytes.withUnsafeBytes { result.append(contentsOf: $0) }
        return result
    }

    public mutating func readRemaining() -> [UInt8] {
        let byteCount = cursor.remainingCount
        do {
            return try readBytes(byteCount)
        } catch {
            preconditionFailure("A cursor failed to consume its own remaining span")
        }
    }

    public mutating func readUInt8() throws(ByteError) -> UInt8 {
        try cursor.readByte()
    }

    public mutating func readUInt16() throws(ByteError) -> UInt16 {
        try cursor.readUInt16BigEndian()
    }

    public mutating func readUInt24() throws(ByteError) -> UInt32 {
        try cursor.readUInt24BigEndian()
    }

    public mutating func readUInt32() throws(ByteError) -> UInt32 {
        try cursor.readUInt32BigEndian()
    }

    public mutating func readUInt64() throws(ByteError) -> UInt64 {
        try cursor.readUInt64BigEndian()
    }

    public mutating func readVector8() throws(ByteError) -> [UInt8] {
        try readBytes(Int(readUInt8()))
    }

    public mutating func readVector16() throws(ByteError) -> [UInt8] {
        try readBytes(Int(readUInt16()))
    }

    public mutating func readVector24() throws(ByteError) -> [UInt8] {
        try readBytes(Int(readUInt24()))
    }

    public mutating func readVector32() throws(ByteError) -> [UInt8] {
        let length = UInt64(try readUInt32())
        guard length <= UInt64(Int.max) else {
            throw .integerDoesNotFit(value: length, byteCount: MemoryLayout<Int>.size)
        }
        return try readBytes(Int(length))
    }

    public func peekUInt8() throws(ByteError) -> UInt8 {
        guard !cursor.isAtEnd else {
            throw .outOfBounds(
                offset: cursor.offset,
                requested: 1,
                available: 0
            )
        }
        return cursor.remainingSpan[0]
    }
}
