import NetworkingCore

/// An owning TLS/DTLS wire builder for fixed-width and length-prefixed fields.
public struct TLSWireWriter: Sendable {
    private var storage: [UInt8]

    public var count: Int { storage.count }

    public init() {
        storage = []
    }

    public init(reservingCapacity capacity: Int) {
        storage = []
        if capacity > 0 {
            storage.reserveCapacity(capacity)
        }
    }

    public mutating func writeByte(_ value: UInt8) {
        storage.append(value)
    }

    public mutating func writeBytes(_ bytes: [UInt8]) {
        storage.append(contentsOf: bytes)
    }

    public mutating func writeSpan(_ bytes: Span<UInt8>) {
        storage.reserveCapacity(storage.count + bytes.count)
        bytes.bytes.withUnsafeBytes { storage.append(contentsOf: $0) }
    }

    public mutating func writeUInt8(_ value: UInt8) {
        storage.append(value)
    }

    public mutating func writeUInt16(_ value: UInt16) {
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeUInt24(_ value: UInt32) throws(ByteError) {
        guard value <= 0xFF_FFFF else {
            throw .integerDoesNotFit(value: UInt64(value), byteCount: 3)
        }
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        storage.append(UInt8(truncatingIfNeeded: value >> 24))
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeUInt64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            storage.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    public mutating func writeVector8(
        _ payload: some Collection<UInt8>
    ) throws(ByteError) {
        guard payload.count <= UInt8.max else {
            throw .integerDoesNotFit(value: UInt64(payload.count), byteCount: 1)
        }
        storage.append(UInt8(payload.count))
        storage.append(contentsOf: payload)
    }

    public mutating func writeVector16(
        _ payload: some Collection<UInt8>
    ) throws(ByteError) {
        guard payload.count <= UInt16.max else {
            throw .integerDoesNotFit(value: UInt64(payload.count), byteCount: 2)
        }
        writeUInt16(UInt16(payload.count))
        storage.append(contentsOf: payload)
    }

    public mutating func writeVector16(_ payload: Span<UInt8>) throws(ByteError) {
        guard payload.count <= UInt16.max else {
            throw .integerDoesNotFit(value: UInt64(payload.count), byteCount: 2)
        }
        writeUInt16(UInt16(payload.count))
        writeSpan(payload)
    }

    public mutating func writeVector24(
        _ payload: some Collection<UInt8>
    ) throws(ByteError) {
        guard payload.count <= 0xFF_FFFF else {
            throw .integerDoesNotFit(value: UInt64(payload.count), byteCount: 3)
        }
        try writeUInt24(UInt32(payload.count))
        storage.append(contentsOf: payload)
    }

    public mutating func writeVector32(
        _ payload: some Collection<UInt8>
    ) throws(ByteError) {
        guard UInt64(payload.count) <= UInt64(UInt32.max) else {
            throw .integerDoesNotFit(value: UInt64(payload.count), byteCount: 4)
        }
        writeUInt32(UInt32(payload.count))
        storage.append(contentsOf: payload)
    }

    public consuming func finishArray() -> [UInt8] {
        storage
    }
}
