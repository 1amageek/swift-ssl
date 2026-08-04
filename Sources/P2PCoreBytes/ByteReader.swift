// ByteReader.swift
// Bounds-checked sequential reader over a byte buffer. Big-endian fixed-width
// ints, QUIC varints, length-prefixed vectors, and sub-slices. Embedded-clean.

/// Sequentially reads from a byte buffer with explicit bounds checking.
///
/// Every read validates that enough bytes remain and throws a typed ``ByteError``
/// instead of trapping, so malformed wire data never crashes the parser. The
/// reader is `~Copyable`: its cursor is single-owner state (no aliasing of the
/// read position, A3). Storage is held as an owned `[UInt8]`; the unread tail is
/// exposed through ``remainingSpan`` (`borrowing get`).
public struct ByteReader: ~Copyable, Sendable {
    @usableFromInline let storage: [UInt8]
    @usableFromInline var cursor: Int

    // MARK: State

    /// Total number of bytes in the buffer.
    @inlinable public var count: Int { storage.count }

    /// Index of the next unread byte.
    @inlinable public var position: Int { cursor }

    /// Number of unread bytes remaining.
    @inlinable public var remaining: Int { storage.count - cursor }

    /// Whether the reader has consumed the whole buffer.
    @inlinable public var isAtEnd: Bool { cursor >= storage.count }

    // MARK: Inits

    /// Creates a reader over an owned array.
    @inlinable public init(_ array: [UInt8]) {
        self.storage = array
        self.cursor = 0
    }

    /// Creates a reader over a ``Bytes`` value.
    @inlinable public init(_ bytes: Bytes) {
        self.storage = bytes.toArray()
        self.cursor = 0
    }

    /// Creates a reader by copying a borrowed typed view into owned storage.
    public init(_ span: Span<UInt8>) {
        var array = [UInt8]()
        array.reserveCapacity(span.count)
        for index in 0..<span.count {
            array.append(span[index])
        }
        self.storage = array
        self.cursor = 0
    }

    // MARK: Borrowed view over the not-yet-consumed tail (EXACT proven form, A3)

    /// A borrowed typed view over the bytes not yet consumed.
    public var remainingSpan: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { storage.span.extracting(cursor..<storage.count) }
    }

    // MARK: Cursor control

    /// Advances the cursor by `count` bytes without returning them.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if
    ///   `count < 0` or fewer than `count` bytes remain.
    public mutating func skip(_ count: Int) throws(ByteError) {
        guard count >= 0, remaining >= count else {
            throw ByteError.insufficientBytes(requested: count, available: remaining)
        }
        cursor += count
    }

    // MARK: Raw bytes

    /// Reads `count` bytes and returns them as an owned array.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if
    ///   `count < 0` or fewer than `count` bytes remain. The cursor does not move
    ///   on failure.
    public mutating func readBytes(_ count: Int) throws(ByteError) -> [UInt8] {
        guard count >= 0, remaining >= count else {
            throw ByteError.insufficientBytes(requested: count, available: remaining)
        }
        var result = [UInt8]()
        result.reserveCapacity(count)
        let end = cursor + count
        var index = cursor
        while index < end {
            result.append(storage[index])
            index += 1
        }
        cursor = end
        return result
    }

    /// Reads `count` bytes and returns them as a ``Bytes`` value.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if fewer
    ///   than `count` bytes remain.
    public mutating func readByteBuffer(_ count: Int) throws(ByteError) -> Bytes {
        Bytes(try readBytes(count))
    }

    /// Reads all remaining bytes as an owned array. Infallible; drains to end.
    public mutating func readRemaining() -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(remaining)
        while cursor < storage.count {
            result.append(storage[cursor])
            cursor += 1
        }
        return result
    }

    // MARK: Fixed-width BIG-ENDIAN integers (QUIC/TLS wire order)

    /// Reads a single `UInt8`.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if the
    ///   buffer is exhausted.
    public mutating func readUInt8() throws(ByteError) -> UInt8 {
        guard remaining >= 1 else {
            throw ByteError.insufficientBytes(requested: 1, available: remaining)
        }
        let value = storage[cursor]
        cursor += 1
        return value
    }

    /// Reads a big-endian `UInt16`.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if fewer
    ///   than 2 bytes remain.
    public mutating func readUInt16() throws(ByteError) -> UInt16 {
        guard remaining >= 2 else {
            throw ByteError.insufficientBytes(requested: 2, available: remaining)
        }
        let b0 = UInt16(storage[cursor])
        let b1 = UInt16(storage[cursor + 1])
        cursor += 2
        return (b0 << 8) | b1
    }

    /// Reads a TLS 3-byte big-endian length into a `UInt32`.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if fewer
    ///   than 3 bytes remain.
    public mutating func readUInt24() throws(ByteError) -> UInt32 {
        guard remaining >= 3 else {
            throw ByteError.insufficientBytes(requested: 3, available: remaining)
        }
        let b0 = UInt32(storage[cursor])
        let b1 = UInt32(storage[cursor + 1])
        let b2 = UInt32(storage[cursor + 2])
        cursor += 3
        return (b0 << 16) | (b1 << 8) | b2
    }

    /// Reads a big-endian `UInt32`.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if fewer
    ///   than 4 bytes remain.
    public mutating func readUInt32() throws(ByteError) -> UInt32 {
        guard remaining >= 4 else {
            throw ByteError.insufficientBytes(requested: 4, available: remaining)
        }
        var value: UInt32 = 0
        var index = 0
        while index < 4 {
            value = (value << 8) | UInt32(storage[cursor + index])
            index += 1
        }
        cursor += 4
        return value
    }

    /// Reads a big-endian `UInt64`.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if fewer
    ///   than 8 bytes remain.
    public mutating func readUInt64() throws(ByteError) -> UInt64 {
        guard remaining >= 8 else {
            throw ByteError.insufficientBytes(requested: 8, available: remaining)
        }
        var value: UInt64 = 0
        var index = 0
        while index < 8 {
            value = (value << 8) | UInt64(storage[cursor + index])
            index += 1
        }
        cursor += 8
        return value
    }

    // MARK: QUIC variable-length integer (RFC 9000 §16)

    /// Reads a QUIC variable-length integer.
    ///
    /// The two most-significant bits of the first byte select the total length
    /// (1, 2, 4, or 8 bytes); the value is the low 6 bits of byte0 followed by the
    /// big-endian remainder.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if the
    ///   encoded integer extends past the end of the buffer.
    public mutating func readVarint() throws(ByteError) -> UInt64 {
        let first = try readUInt8()
        let length = 1 << (first >> 6)
        let extraBytes = length - 1
        guard remaining >= extraBytes else {
            throw ByteError.insufficientBytes(requested: extraBytes, available: remaining)
        }
        var value = UInt64(first & 0x3f)
        var index = 0
        while index < extraBytes {
            value = (value << 8) | UInt64(storage[cursor + index])
            index += 1
        }
        cursor += extraBytes
        return value
    }

    // MARK: Length-prefixed vectors

    /// Reads a vector whose length is a leading QUIC varint (QUIC).
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if the
    ///   varint is truncated or the declared payload exceeds the remaining bytes;
    ///   ``ByteError/lengthOutOfRange`` if the length cannot be an `Int`.
    public mutating func readVarintVector() throws(ByteError) -> [UInt8] {
        let declared = try readVarint()
        let length = try intLength(declared)
        return try readBytes(length)
    }

    /// Reads a vector whose length is a leading `UInt8` (TLS).
    public mutating func readVector8() throws(ByteError) -> [UInt8] {
        let length = Int(try readUInt8())
        return try readBytes(length)
    }

    /// Reads a vector whose length is a leading big-endian `UInt16` (TLS).
    public mutating func readVector16() throws(ByteError) -> [UInt8] {
        let length = Int(try readUInt16())
        return try readBytes(length)
    }

    /// Reads a vector whose length is a leading big-endian `UInt24` (TLS).
    public mutating func readVector24() throws(ByteError) -> [UInt8] {
        let length = Int(try readUInt24())
        return try readBytes(length)
    }

    /// Reads a vector whose length is a leading big-endian `UInt32`.
    public mutating func readVector32() throws(ByteError) -> [UInt8] {
        let length = try intLength(UInt64(try readUInt32()))
        return try readBytes(length)
    }

    // MARK: Sub-reader / sub-slice over the next `length` bytes (TLS subReader)

    /// Reads `length` bytes and returns them wrapped in a fresh, independent
    /// ``ByteReader``; the parent cursor advances by `length`.
    public mutating func subReader(length: Int) throws(ByteError) -> ByteReader {
        ByteReader(try readBytes(length))
    }

    // MARK: Lookahead (non-consuming)

    /// Returns the next byte without advancing.
    ///
    /// - Throws: ``ByteError/insufficientBytes(requested:available:)`` if the
    ///   buffer is exhausted.
    public func peekUInt8() throws(ByteError) -> UInt8 {
        guard remaining >= 1 else {
            throw ByteError.insufficientBytes(requested: 1, available: remaining)
        }
        return storage[cursor]
    }

    /// Returns the encoded width (1/2/4/8) of the next varint without advancing,
    /// or `nil` at end of input.
    public func peekVarintLength() -> Int? {
        guard cursor < storage.count else { return nil }
        return 1 << (storage[cursor] >> 6)
    }

    // MARK: Helpers

    /// Converts a wire length to `Int`, rejecting values that overflow.
    @usableFromInline
    func intLength(_ value: UInt64) throws(ByteError) -> Int {
        guard value <= UInt64(Int.max) else {
            throw ByteError.lengthOutOfRange
        }
        return Int(value)
    }
}
