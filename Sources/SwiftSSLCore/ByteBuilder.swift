public struct ByteBuilder: Sendable {
    private var storage: ContiguousArray<UInt8>
    public let maximumByteCount: Int

    public init(maximumByteCount: Int, minimumCapacity: Int = 0) throws(ByteError) {
        guard maximumByteCount >= 0 else {
            throw .negativeCount(maximumByteCount)
        }
        guard minimumCapacity >= 0 else {
            throw .negativeCount(minimumCapacity)
        }
        guard minimumCapacity <= maximumByteCount else {
            throw .capacityExceeded(limit: maximumByteCount, attempted: minimumCapacity)
        }

        storage = []
        storage.reserveCapacity(minimumCapacity)
        self.maximumByteCount = maximumByteCount
    }

    public var count: Int {
        storage.count
    }

    public var remainingCapacity: Int {
        maximumByteCount - storage.count
    }

    public mutating func append(_ byte: UInt8) throws(ByteError) {
        try requireCapacity(forAdditionalByteCount: 1)
        storage.append(byte)
    }

    public mutating func append(_ bytes: Span<UInt8>) throws(ByteError) {
        try requireCapacity(forAdditionalByteCount: bytes.count)

        var index = 0
        while index < bytes.count {
            storage.append(bytes[index])
            index += 1
        }
    }

    public mutating func appendUInt16BigEndian(_ value: UInt16) throws(ByteError) {
        try requireCapacity(forAdditionalByteCount: 2)
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func appendUInt24BigEndian(_ value: UInt32) throws(ByteError) {
        guard value <= 0x00FF_FFFF else {
            throw .integerDoesNotFit(value: UInt64(value), byteCount: 3)
        }
        try requireCapacity(forAdditionalByteCount: 3)
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func appendUInt32BigEndian(_ value: UInt32) throws(ByteError) {
        try requireCapacity(forAdditionalByteCount: 4)
        storage.append(UInt8(truncatingIfNeeded: value >> 24))
        storage.append(UInt8(truncatingIfNeeded: value >> 16))
        storage.append(UInt8(truncatingIfNeeded: value >> 8))
        storage.append(UInt8(truncatingIfNeeded: value))
    }

    public consuming func finish() -> OwnedBytes {
        OwnedBytes(consuming: storage)
    }

    private func requireCapacity(forAdditionalByteCount byteCount: Int) throws(ByteError) {
        guard byteCount >= 0 else {
            throw .negativeCount(byteCount)
        }

        let (attempted, overflow) = storage.count.addingReportingOverflow(byteCount)
        guard !overflow else {
            throw .offsetOverflow(offset: storage.count, count: byteCount)
        }
        guard attempted <= maximumByteCount else {
            throw .capacityExceeded(limit: maximumByteCount, attempted: attempted)
        }
    }
}
