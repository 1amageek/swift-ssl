import SwiftSSLCore

public struct DERWriter: Sendable {
    private var builder: ByteBuilder

    public init(maximumByteCount: Int, minimumCapacity: Int = 0) throws(DERWriteError) {
        do {
            builder = try ByteBuilder(
                maximumByteCount: maximumByteCount,
                minimumCapacity: minimumCapacity
            )
        } catch {
            throw .capacity(error)
        }
    }

    public var count: Int { builder.count }

    public mutating func append(
        tag: DERTag,
        content: Span<UInt8>
    ) throws(DERWriteError) {
        let tagByteCount = tag.number < 31
            ? 1
            : 1 + ((UInt.bitWidth - tag.number.leadingZeroBitCount + 6) / 7)
        let lengthByteCount: Int
        if content.count < 128 {
            lengthByteCount = 1
        } else {
            let significantBits = Int.bitWidth - content.count.leadingZeroBitCount
            lengthByteCount = 1 + ((significantBits + 7) / 8)
        }
        let (headerByteCount, headerOverflow) = tagByteCount.addingReportingOverflow(lengthByteCount)
        let (totalByteCount, totalOverflow) = headerByteCount.addingReportingOverflow(content.count)
        guard !headerOverflow, !totalOverflow else {
            throw .capacity(.offsetOverflow(offset: builder.count, count: content.count))
        }
        guard totalByteCount <= builder.remainingCapacity else {
            throw .capacity(.capacityExceeded(
                limit: builder.maximumByteCount,
                attempted: builder.count + totalByteCount
            ))
        }
        do {
            try appendTag(tag)
            try appendLength(content.count)
            try builder.append(content)
        } catch {
            throw .capacity(error)
        }
    }

    public mutating func appendPositiveInteger(
        _ value: UInt64
    ) throws(DERWriteError) {
        var bytes = ContiguousArray<UInt8>()
        var current = value
        repeat {
            bytes.append(UInt8(truncatingIfNeeded: current))
            current >>= 8
        } while current != 0
        bytes.reverse()
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        try append(
            tag: DERTag(tagClass: .universal, isConstructed: false, number: 2),
            content: bytes.span
        )
    }

    public mutating func appendBoolean(_ value: Bool) throws(DERWriteError) {
        let content: ContiguousArray<UInt8> = [value ? 0xFF : 0]
        try append(
            tag: DERTag(tagClass: .universal, isConstructed: false, number: 1),
            content: content.span
        )
    }

    public consuming func finish() -> OwnedBytes {
        builder.finish()
    }

    private mutating func appendTag(_ tag: DERTag) throws(ByteError) {
        let classBits = UInt8(tag.tagClass.rawValue) << 6
        let constructedBit: UInt8 = tag.isConstructed ? 0x20 : 0
        guard tag.number < 31 else {
            try builder.append(classBits | constructedBit | 0x1F)
            var encoded = ContiguousArray<UInt8>()
            var value = tag.number
            repeat {
                encoded.append(UInt8(value & 0x7F))
                value >>= 7
            } while value != 0
            var index = encoded.count
            while index > 0 {
                index -= 1
                let continuation: UInt8 = index == 0 ? 0 : 0x80
                try builder.append(encoded[index] | continuation)
            }
            return
        }
        try builder.append(classBits | constructedBit | UInt8(tag.number))
    }

    private mutating func appendLength(_ length: Int) throws(ByteError) {
        guard length >= 0 else {
            throw .negativeCount(length)
        }
        if length < 128 {
            try builder.append(UInt8(length))
            return
        }
        var encoded = ContiguousArray<UInt8>()
        var value = length
        while value > 0 {
            encoded.append(UInt8(truncatingIfNeeded: value))
            value >>= 8
        }
        guard encoded.count <= 4 else {
            throw .integerDoesNotFit(value: UInt64(length), byteCount: 4)
        }
        try builder.append(0x80 | UInt8(encoded.count))
        var index = encoded.count
        while index > 0 {
            index -= 1
            try builder.append(encoded[index])
        }
    }
}
