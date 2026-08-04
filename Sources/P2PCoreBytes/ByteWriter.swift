// ByteWriter.swift
// Append-oriented byte builder. Big-endian fixed-width ints (incl. UInt24),
// QUIC varints, length-prefixed vectors, and a back-patched length-prefix.
// Embedded-clean: no Foundation, no `any`.

/// Builds a byte buffer by appending fixed-width integers (big-endian), QUIC
/// variable-length integers, and length-prefixed vectors.
///
/// Appends are infallible; the vector and `UInt24` helpers reject values that do
/// not fit their fixed-width prefix with a typed ``ByteError``.
public struct ByteWriter: Sendable {
    @usableFromInline var storage: [UInt8]

    /// The number of bytes written so far.
    @inlinable public var count: Int { storage.count }

    /// Creates an empty writer.
    @inlinable public init() {
        self.storage = []
    }

    /// Creates a writer with reserved capacity.
    @inlinable public init(reservingCapacity capacity: Int) {
        self.storage = []
        if capacity > 0 {
            self.storage.reserveCapacity(capacity)
        }
    }

    // MARK: Raw

    /// Appends a single byte.
    @inlinable public mutating func writeByte(_ value: UInt8) {
        storage.append(value)
    }

    /// Appends a sequence of bytes.
    @inlinable public mutating func writeBytes(_ sequence: some Sequence<UInt8>) {
        storage.append(contentsOf: sequence)
    }

    /// Appends a borrowed typed view (zero-copy from caller storage).
    public mutating func writeSpan(_ span: Span<UInt8>) {
        storage.reserveCapacity(storage.count + span.count)
        for index in 0..<span.count {
            storage.append(span[index])
        }
    }

    /// Appends the contents of a ``Bytes`` value.
    public mutating func writeBytes(_ value: Bytes) {
        writeSpan(value.span)
    }

    // MARK: Fixed-width BIG-ENDIAN

    /// Appends a `UInt8`.
    @inlinable public mutating func writeUInt8(_ value: UInt8) {
        storage.append(value)
    }

    /// Appends a `UInt16` in big-endian order.
    @inlinable public mutating func writeUInt16(_ value: UInt16) {
        storage.append(UInt8((value >> 8) & 0xff))
        storage.append(UInt8(value & 0xff))
    }

    /// Appends a 3-byte (TLS) big-endian length.
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if `value > 0xFFFFFF`.
    public mutating func writeUInt24(_ value: UInt32) throws(ByteError) {
        guard value <= 0xFF_FFFF else {
            throw ByteError.lengthOutOfRange
        }
        storage.append(UInt8((value >> 16) & 0xff))
        storage.append(UInt8((value >> 8) & 0xff))
        storage.append(UInt8(value & 0xff))
    }

    /// Appends a `UInt32` in big-endian order.
    @inlinable public mutating func writeUInt32(_ value: UInt32) {
        storage.append(UInt8((value >> 24) & 0xff))
        storage.append(UInt8((value >> 16) & 0xff))
        storage.append(UInt8((value >> 8) & 0xff))
        storage.append(UInt8(value & 0xff))
    }

    /// Appends a `UInt64` in big-endian order.
    @inlinable public mutating func writeUInt64(_ value: UInt64) {
        var shift = 56
        while shift >= 0 {
            storage.append(UInt8((value >> UInt64(shift)) & 0xff))
            shift -= 8
        }
    }

    // MARK: QUIC varint

    /// The largest value encodable as a QUIC varint (`2^62 - 1`).
    public static var maxVarint: UInt64 { (UInt64(1) << 62) - 1 }

    /// Appends a value using the QUIC variable-length integer encoding.
    ///
    /// - Throws: ``ByteError/invalidVarint`` if `value` exceeds ``maxVarint``.
    public mutating func writeVarint(_ value: UInt64) throws(ByteError) {
        guard value <= ByteWriter.maxVarint else {
            throw ByteError.invalidVarint
        }
        if value <= 63 {
            storage.append(UInt8(value))
        } else if value <= 16383 {
            storage.append(UInt8(0x40 | ((value >> 8) & 0x3f)))
            storage.append(UInt8(value & 0xff))
        } else if value <= 1_073_741_823 {
            storage.append(UInt8(0x80 | ((value >> 24) & 0x3f)))
            storage.append(UInt8((value >> 16) & 0xff))
            storage.append(UInt8((value >> 8) & 0xff))
            storage.append(UInt8(value & 0xff))
        } else {
            storage.append(UInt8(0xc0 | ((value >> 56) & 0x3f)))
            var shift = 48
            while shift >= 0 {
                storage.append(UInt8((value >> UInt64(shift)) & 0xff))
                shift -= 8
            }
        }
    }

    // MARK: Length-prefixed vectors (reject payloads that overflow the prefix width)

    /// Writes `payload` preceded by its length as a QUIC varint.
    ///
    /// - Throws: ``ByteError/invalidVarint`` if the payload length exceeds the
    ///   varint range.
    public mutating func writeVarintVector(_ payload: some Collection<UInt8>) throws(ByteError) {
        try writeVarint(UInt64(payload.count))
        storage.append(contentsOf: payload)
    }

    /// Writes `payload` preceded by its length as a `UInt8`.
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if the payload is longer than `0xFF`.
    public mutating func writeVector8(_ payload: some Collection<UInt8>) throws(ByteError) {
        guard payload.count <= 0xFF else {
            throw ByteError.lengthOutOfRange
        }
        storage.append(UInt8(payload.count))
        storage.append(contentsOf: payload)
    }

    /// Writes `payload` preceded by its length as a big-endian `UInt16`.
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if the payload is longer than `0xFFFF`.
    public mutating func writeVector16(_ payload: some Collection<UInt8>) throws(ByteError) {
        guard payload.count <= 0xFFFF else {
            throw ByteError.lengthOutOfRange
        }
        writeUInt16(UInt16(payload.count))
        storage.append(contentsOf: payload)
    }

    /// Writes `payload` preceded by its length as a big-endian `UInt24` (TLS).
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if the payload is longer than `0xFFFFFF`.
    public mutating func writeVector24(_ payload: some Collection<UInt8>) throws(ByteError) {
        guard payload.count <= 0xFF_FFFF else {
            throw ByteError.lengthOutOfRange
        }
        try writeUInt24(UInt32(payload.count))
        storage.append(contentsOf: payload)
    }

    /// Writes `payload` preceded by its length as a big-endian `UInt32`.
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if the payload is longer than `0xFFFFFFFF`.
    public mutating func writeVector32(_ payload: some Collection<UInt8>) throws(ByteError) {
        guard UInt64(payload.count) <= 0xFFFF_FFFF else {
            throw ByteError.lengthOutOfRange
        }
        writeUInt32(UInt32(payload.count))
        storage.append(contentsOf: payload)
    }

    // MARK: Deferred-length (back-patched) vector for nested TLS/QUIC structures

    /// Reserves a 3-byte length, runs `body`, then patches the big-endian length
    /// of the bytes `body` wrote. Avoids a two-pass size computation (A5).
    ///
    /// - Throws: ``ByteError/lengthOutOfRange`` if the body wrote more than
    ///   `0xFFFFFF` bytes, plus any error thrown by `body`.
    public mutating func writeLengthPrefixed24(
        _ body: (inout ByteWriter) throws(ByteError) -> Void
    ) throws(ByteError) {
        let lengthOffset = storage.count
        storage.append(0)
        storage.append(0)
        storage.append(0)
        let bodyStart = storage.count
        try body(&self)
        let bodyLen = storage.count - bodyStart
        guard bodyLen <= 0xFF_FFFF else {
            throw ByteError.lengthOutOfRange
        }
        let length = UInt32(bodyLen)
        storage[lengthOffset]     = UInt8((length >> 16) & 0xff)
        storage[lengthOffset + 1] = UInt8((length >> 8) & 0xff)
        storage[lengthOffset + 2] = UInt8(length & 0xff)
    }

    // MARK: Finalization

    /// Returns the accumulated bytes as a ``Bytes`` value.
    public func finish() -> Bytes {
        Bytes(storage)
    }

    /// Returns the accumulated bytes as an owned array.
    public func finishArray() -> [UInt8] {
        storage
    }
}
