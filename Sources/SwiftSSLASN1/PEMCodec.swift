import SwiftSSLCore

public enum PEMCodec {
    public static let defaultMaximumDERByteCount = 16 * 1024 * 1024
    public static let maximumBase64LineByteCount = 64

    public static func decode(
        _ source: Span<UInt8>,
        maximumDERByteCount: Int = Self.defaultMaximumDERByteCount
    ) throws(PEMError) -> PEMBlock {
        guard maximumDERByteCount > 0 else {
            throw .outputLimitExceeded(limit: maximumDERByteCount, attempted: 1)
        }

        var offset = 0
        let beginLine = try readLine(source, offset: &offset)
        guard beginLine.count >= 16 else {
            throw .missingBeginBoundary
        }
        let beginPrefix: [UInt8] = [
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20
        ]
        guard hasPrefix(beginLine, beginPrefix), hasSuffix(beginLine, [0x2D, 0x2D, 0x2D, 0x2D, 0x2D]) else {
            throw .missingBeginBoundary
        }
        let labelBytes = beginLine.extracting(11..<(beginLine.count - 5))
        let label = try decodeLabel(labelBytes)

        var builder: ByteBuilder
        do {
            builder = try ByteBuilder(maximumByteCount: maximumDERByteCount)
        } catch {
            throw .outputLimitExceeded(limit: maximumDERByteCount, attempted: 1)
        }

        var quartet = ContiguousArray<UInt8>()
        quartet.reserveCapacity(4)
        var sawPayload = false
        var sawPadding = false
        while true {
            guard offset <= source.count else {
                throw .missingEndBoundary
            }
            let line = try readLine(source, offset: &offset)
            if hasPrefix(line, [0x2D, 0x2D, 0x2D, 0x2D, 0x2D]) {
                let endPrefix: [UInt8] = [
                    0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20
                ]
                guard hasPrefix(line, endPrefix), hasSuffix(line, [0x2D, 0x2D, 0x2D, 0x2D, 0x2D]) else {
                    throw .invalidBoundary
                }
                let endLabelBytes = line.extracting(9..<(line.count - 5))
                let endLabel = try decodeLabel(endLabelBytes)
                guard endLabel == label else {
                    throw .boundaryLabelMismatch
                }
                guard !sawPadding || quartet.isEmpty else {
                    throw .invalidBase64Padding(offset: offset)
                }
                guard quartet.isEmpty else {
                    throw .truncatedBase64
                }
                guard sawPayload else {
                    throw .emptyPayload
                }
                guard offset == source.count else {
                    throw .trailingData(offset: offset)
                }
                let der = builder.finish()
                do {
                    return try PEMBlock(label: label, der: der)
                } catch {
                    throw error
                }
            }

            guard !line.isEmpty else {
                throw .invalidBoundary
            }
            guard line.count <= Self.maximumBase64LineByteCount else {
                throw .lineTooLong(offset: offset - line.count, limit: Self.maximumBase64LineByteCount)
            }
            var index = 0
            while index < line.count {
                let byte = line[index]
                let byteOffset = offset - line.count + index
                guard isBase64Byte(byte) else {
                    throw .invalidBase64Character(offset: byteOffset)
                }
                if sawPadding {
                    throw .invalidBase64Padding(offset: byteOffset)
                }
                if byte == 0x3D {
                    guard quartet.count >= 2 else {
                        throw .invalidBase64Padding(offset: byteOffset)
                    }
                    if quartet.count == 2 {
                        guard index + 1 < line.count, line[index + 1] == 0x3D else {
                            throw .invalidBase64Padding(offset: byteOffset)
                        }
                    }
                }
                quartet.append(byte)
                if quartet.count == 4 {
                    try decodeQuartet(
                        quartet.span,
                        into: &builder,
                        sourceOffset: byteOffset - 3
                    )
                    sawPayload = true
                    sawPadding = quartet[2] == 0x3D || quartet[3] == 0x3D
                    quartet.removeAll(keepingCapacity: true)
                }
                index += 1
            }
        }
    }

    public static func encode(
        _ block: borrowing PEMBlock,
        maximumByteCount: Int = defaultMaximumEncodedByteCount
    ) throws(PEMError) -> OwnedBytes {
        let label = block.label
        return try block.withDERBytes { (der: Span<UInt8>) throws(PEMError) -> OwnedBytes in
            try encode(
                label: label,
                der: der,
                maximumByteCount: maximumByteCount
            )
        }
    }

    public static func encode(
        label: String,
        der: Span<UInt8>,
        maximumByteCount: Int = defaultMaximumEncodedByteCount
    ) throws(PEMError) -> OwnedBytes {
        guard PEMBlock.isValidLabel(label) else {
            throw .invalidLabel
        }
        guard der.count > 0 else {
            throw .emptyDER
        }
        guard maximumByteCount >= 0 else {
            throw .outputLimitExceeded(limit: maximumByteCount, attempted: 1)
        }
        let (base64ByteCount, base64Overflow) = der.count
            .addingReportingOverflow(2)
        guard !base64Overflow else {
            throw .integerOverflow
        }
        let quartetCount = base64ByteCount / 3
        let (encodedBase64Count, encodedOverflow) = quartetCount.multipliedReportingOverflow(by: 4)
        guard !encodedOverflow else {
            throw .integerOverflow
        }
        let lineBreakCount = (encodedBase64Count - 1) / maximumBase64LineByteCount + 1
        var total = 0
        for count in [
            11,
            label.utf8.count,
            6,
            encodedBase64Count,
            lineBreakCount,
            9,
            label.utf8.count,
            6
        ] {
            let (updated, overflow) = total.addingReportingOverflow(count)
            guard !overflow else {
                throw .integerOverflow
            }
            total = updated
        }
        guard total <= maximumByteCount else {
            throw .outputLimitExceeded(limit: maximumByteCount, attempted: total)
        }

        var builder: ByteBuilder
        do {
            builder = try ByteBuilder(maximumByteCount: maximumByteCount, minimumCapacity: total)
        } catch {
            throw .outputLimitExceeded(limit: maximumByteCount, attempted: total)
        }
        let beginPrefix: [UInt8] = [
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20
        ]
        let endPrefix: [UInt8] = [
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20
        ]
        do {
            try appendArray(beginPrefix, to: &builder)
            try appendLabel(label, to: &builder)
            try appendArray([0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A], to: &builder)

            var sourceOffset = 0
            var lineLength = 0
            while sourceOffset < der.count {
                let remaining = der.count - sourceOffset
                let first = der[sourceOffset]
                let second = remaining > 1 ? der[sourceOffset + 1] : 0
                let third = remaining > 2 ? der[sourceOffset + 2] : 0
                let quartet: [UInt8] = [
                    base64Alphabet[Int(first >> 2)],
                    base64Alphabet[Int(((first & 0x03) << 4) | (second >> 4))],
                    remaining > 1
                        ? base64Alphabet[Int(((second & 0x0F) << 2) | (third >> 6))]
                        : 0x3D,
                    remaining > 2 ? base64Alphabet[Int(third & 0x3F)] : 0x3D
                ]
                for byte in quartet {
                    try builder.append(byte)
                    lineLength += 1
                    if lineLength == maximumBase64LineByteCount {
                        try builder.append(0x0A)
                        lineLength = 0
                    }
                }
                sourceOffset += remaining >= 3 ? 3 : remaining
            }
            if lineLength != 0 {
                try builder.append(0x0A)
            }
            try appendArray(endPrefix, to: &builder)
            try appendLabel(label, to: &builder)
            try appendArray([0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x0A], to: &builder)
        } catch {
            throw .outputLimitExceeded(limit: maximumByteCount, attempted: total)
        }
        return builder.finish()
    }

    public static let defaultMaximumEncodedByteCount = 24 * 1024 * 1024

    private static let base64Alphabet: [UInt8] = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+".utf8
    ) + [0x2F]

    private static func decodeLabel(_ bytes: Span<UInt8>) throws(PEMError) -> String {
        var labelBytes = ContiguousArray<UInt8>()
        labelBytes.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            labelBytes.append(bytes[index])
            index += 1
        }
        let label = String(decoding: labelBytes, as: UTF8.self)
        guard label.utf8.count == labelBytes.count, PEMBlock.isValidLabel(label) else {
            throw .invalidLabel
        }
        return label
    }

    private static func readLine(
        _ source: Span<UInt8>,
        offset: inout Int
    ) throws(PEMError) -> Span<UInt8> {
        let start = offset
        while offset < source.count, source[offset] != 0x0A {
            guard source[offset] != 0x0D else {
                guard offset + 1 < source.count, source[offset + 1] == 0x0A else {
                    throw .invalidLineBreak(offset: offset)
                }
                offset += 1
                continue
            }
            offset += 1
        }
        let end = offset > start && source[offset - 1] == 0x0D
            ? offset - 1
            : offset
        let line = source.extracting(start..<end)
        if offset < source.count {
            offset += 1
        }
        return line
    }

    private static func hasPrefix(_ value: Span<UInt8>, _ prefix: [UInt8]) -> Bool {
        guard value.count >= prefix.count else {
            return false
        }
        var index = 0
        while index < prefix.count {
            guard value[index] == prefix[index] else {
                return false
            }
            index += 1
        }
        return true
    }

    private static func hasSuffix(_ value: Span<UInt8>, _ suffix: [UInt8]) -> Bool {
        guard value.count >= suffix.count else {
            return false
        }
        let start = value.count - suffix.count
        var index = 0
        while index < suffix.count {
            guard value[start + index] == suffix[index] else {
                return false
            }
            index += 1
        }
        return true
    }

    private static func isBase64Byte(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A)
            || (byte >= 0x61 && byte <= 0x7A)
            || (byte >= 0x30 && byte <= 0x39)
            || byte == 0x2B
            || byte == 0x2F
            || byte == 0x3D
    }

    private static func decodeQuartet(
        _ quartet: Span<UInt8>,
        into builder: inout ByteBuilder,
        sourceOffset: Int
    ) throws(PEMError) {
        let first = try decodeBase64Value(quartet[0], offset: sourceOffset)
        let second = try decodeBase64Value(quartet[1], offset: sourceOffset + 1)
        let third = quartet[2]
        let fourth = quartet[3]
        guard third != 0x3D || fourth == 0x3D else {
            throw .invalidBase64Padding(offset: sourceOffset + 2)
        }
        if third == 0x3D {
            guard fourth == 0x3D, (second & 0x0F) == 0 else {
                throw .nonCanonicalBase64(offset: sourceOffset + 1)
            }
            do {
                try builder.append((first << 2) | (second >> 4))
            } catch {
                throw .outputLimitExceeded(limit: builder.maximumByteCount, attempted: builder.count + 1)
            }
            return
        }
        let thirdValue = try decodeBase64Value(third, offset: sourceOffset + 2)
        do {
            try builder.append((first << 2) | (second >> 4))
            try builder.append((second << 4) | (thirdValue >> 2))
        } catch {
            throw .outputLimitExceeded(limit: builder.maximumByteCount, attempted: builder.count + 1)
        }
        if fourth == 0x3D {
            guard (thirdValue & 0x03) == 0 else {
                throw .nonCanonicalBase64(offset: sourceOffset + 2)
            }
            return
        }
        let fourthValue = try decodeBase64Value(fourth, offset: sourceOffset + 3)
        do {
            try builder.append((thirdValue << 6) | fourthValue)
        } catch {
            throw .outputLimitExceeded(limit: builder.maximumByteCount, attempted: builder.count + 1)
        }
    }

    private static func decodeBase64Value(
        _ byte: UInt8,
        offset: Int
    ) throws(PEMError) -> UInt8 {
        switch byte {
        case 0x41...0x5A:
            return byte - 0x41
        case 0x61...0x7A:
            return byte - 0x61 + 26
        case 0x30...0x39:
            return byte - 0x30 + 52
        case 0x2B:
            return 62
        case 0x2F:
            return 63
        default:
            throw .invalidBase64Character(offset: offset)
        }
    }

    private static func appendArray(
        _ bytes: [UInt8],
        to builder: inout ByteBuilder
    ) throws(ByteError) {
        for byte in bytes {
            try builder.append(byte)
        }
    }

    private static func appendLabel(
        _ label: String,
        to builder: inout ByteBuilder
    ) throws(ByteError) {
        for byte in label.utf8 {
            try builder.append(byte)
        }
    }
}
