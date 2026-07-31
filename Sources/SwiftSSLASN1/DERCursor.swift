import SwiftSSLCore

public struct DERCursor: ~Escapable {
    private static let maximumLengthByteCount = 4

    private let bytes: Span<UInt8>
    private var cursor: ByteCursor

    @_lifetime(copy bytes)
    public init(_ bytes: Span<UInt8>) {
        self.bytes = bytes
        cursor = ByteCursor(bytes)
    }

    public var remainingCount: Int {
        cursor.remainingCount
    }

    public var isAtEnd: Bool {
        cursor.isAtEnd
    }

    @_lifetime(copy self)
    public mutating func readElement(
        using budget: inout ParsingBudget
    ) throws(DERError) -> DERElementView {
        do {
            try budget.consumeElement()
        } catch {
            throw .resourceLimit(error)
        }

        let elementOffset = cursor.offset
        let tag = try readTag()
        let contentByteCount = try readLength()
        let contentOffset = cursor.offset

        do {
            try cursor.skip(count: contentByteCount)
        } catch let error {
            throw Self.mapByteError(error, fallbackOffset: contentOffset)
        }

        let encodedByteCount = cursor.offset - elementOffset
        let encoded = bytes.extracting(
            elementOffset..<(elementOffset + encodedByteCount)
        )
        return DERElementView(
            tag: tag,
            headerByteCount: contentOffset - elementOffset,
            encodedBytes: encoded
        )
    }

    public func requireFullyConsumed() throws(DERError) {
        guard cursor.isAtEnd else {
            throw .trailingData(count: cursor.remainingCount)
        }
    }

    private mutating func readTag() throws(DERError) -> DERTag {
        let tagOffset = cursor.offset
        let first = try readByte()
        guard let tagClass = DERTagClass(rawValue: first >> 6) else {
            throw .invalidTag(offset: tagOffset)
        }

        let isConstructed = (first & 0x20) != 0
        let lowTagNumber = first & 0x1F
        guard lowTagNumber == 0x1F else {
            return DERTag(
                tagClass: tagClass,
                isConstructed: isConstructed,
                number: UInt(lowTagNumber)
            )
        }

        var number: UInt = 0
        var byteIndex = 0
        while true {
            let byteOffset = cursor.offset
            let byte = try readByte()
            if byteIndex == 0, (byte & 0x7F) == 0 {
                throw .nonMinimalTag(offset: byteOffset)
            }

            let (shifted, shiftOverflow) = number.multipliedReportingOverflow(by: 128)
            let (updated, addOverflow) = shifted.addingReportingOverflow(UInt(byte & 0x7F))
            guard !shiftOverflow, !addOverflow else {
                throw .tagNumberOverflow(offset: byteOffset)
            }
            number = updated
            byteIndex += 1

            if (byte & 0x80) == 0 {
                break
            }
        }

        guard number >= 31 else {
            throw .nonMinimalTag(offset: tagOffset)
        }
        return DERTag(tagClass: tagClass, isConstructed: isConstructed, number: number)
    }

    private mutating func readLength() throws(DERError) -> Int {
        let lengthOffset = cursor.offset
        let first = try readByte()
        if (first & 0x80) == 0 {
            return Int(first)
        }

        let lengthByteCount = Int(first & 0x7F)
        guard lengthByteCount != 0 else {
            throw .indefiniteLength(offset: lengthOffset)
        }
        guard lengthByteCount <= Self.maximumLengthByteCount else {
            throw .lengthByteCountExceeded(
                offset: lengthOffset,
                limit: Self.maximumLengthByteCount,
                actual: lengthByteCount
            )
        }

        var length = 0
        for index in 0..<lengthByteCount {
            let byteOffset = cursor.offset
            let byte = try readByte()
            if index == 0, byte == 0 {
                throw .nonMinimalLength(offset: byteOffset)
            }

            let (shifted, shiftOverflow) = length.multipliedReportingOverflow(by: 256)
            let (updated, addOverflow) = shifted.addingReportingOverflow(Int(byte))
            guard !shiftOverflow, !addOverflow else {
                throw .lengthOverflow(offset: byteOffset)
            }
            length = updated
        }

        guard length >= 128 else {
            throw .nonMinimalLength(offset: lengthOffset)
        }
        return length
    }

    private mutating func readByte() throws(DERError) -> UInt8 {
        do {
            return try cursor.readByte()
        } catch let error {
            throw Self.mapByteError(error, fallbackOffset: cursor.offset)
        }
    }

    private static func mapByteError(
        _ error: ByteError,
        fallbackOffset: Int
    ) -> DERError {
        switch error {
        case let .outOfBounds(offset, requested, available):
            return .truncated(offset: offset, requested: requested, available: available)
        case let .offsetOverflow(offset, _):
            return .lengthOverflow(offset: offset)
        case .negativeCount:
            return .lengthOverflow(offset: fallbackOffset)
        case let .trailingBytes(count):
            return .trailingData(count: count)
        case .capacityExceeded, .integerDoesNotFit:
            return .lengthOverflow(offset: fallbackOffset)
        }
    }
}
