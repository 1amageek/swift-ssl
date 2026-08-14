import SSLCore

/// Strict conversion between fixed-width IEEE P1363 ECDSA signatures and the
/// canonical ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` representation.
public enum DERECDSASignatureCodec {
    public static func encode(
        rawSignature: Span<UInt8>,
        scalarByteCount: Int
    ) throws(DERECDSASignatureError) -> OwnedBytes {
        let expected = try validatedRawByteCount(scalarByteCount: scalarByteCount)
        guard rawSignature.count == expected else {
            throw .invalidRawSignatureLength(expected: expected, actual: rawSignature.count)
        }

        let r = rawSignature.extracting(0..<scalarByteCount)
        let s = rawSignature.extracting(scalarByteCount..<expected)
        let rInteger = try encodeInteger(r, scalarByteCount: scalarByteCount)
        let sInteger = try encodeInteger(s, scalarByteCount: scalarByteCount)
        let contentCount = rInteger.count + sInteger.count
        let maximum = contentCount + Self.maximumHeaderByteCount
        var writer: DERWriter
        do {
            writer = try DERWriter(maximumByteCount: maximum, minimumCapacity: maximum)
            var content = try ByteBuilder(
                maximumByteCount: contentCount,
                minimumCapacity: contentCount
            )
            try content.append(rInteger.span)
            try content.append(sInteger.span)
            let encodedContent = content.finish()
            try writer.append(tag: sequenceTag, content: encodedContent.span)
        } catch let error as DERWriteError {
            throw .write(error)
        } catch let error as ByteError {
            throw .bytes(error)
        } catch {
            preconditionFailure("DER ECDSA encoding has a closed typed-error surface")
        }
        return writer.finish()
    }

    public static func decode(
        derSignature: Span<UInt8>,
        scalarByteCount: Int,
        limits: ParsingLimits = defaultParsingLimits
    ) throws(DERECDSASignatureError) -> OwnedBytes {
        let outputCount = try validatedRawByteCount(scalarByteCount: scalarByteCount)
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: derSignature.count)
        } catch let error {
            throw .resourceLimit(error)
        }
        var cursor = DERCursor(derSignature)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        guard root.tag == sequenceTag else { throw .invalidStructure }

        var body = DERCursor(root.contentBytes)
        let r: DERElementView
        let s: DERElementView
        do {
            r = try body.readElement(using: &budget)
            s = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }

        var output = ContiguousArray<UInt8>(repeating: 0, count: outputCount)
        try copyCanonicalInteger(r, into: &output, offset: 0, scalarByteCount: scalarByteCount)
        try copyCanonicalInteger(
            s,
            into: &output,
            offset: scalarByteCount,
            scalarByteCount: scalarByteCount
        )
        return OwnedBytes(consuming: output)
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 1024,
                maximumNestingDepth: 4,
                maximumElementCount: 3,
                maximumExtensionCount: 1,
                maximumOIDBytes: 1,
                maximumStringBytes: 1
            )
        } catch {
            preconditionFailure("ECDSA signature limits are compile-time constants")
        }
    }()

    private static let maximumHeaderByteCount = 6
    private static let integerTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 2
    )
    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )

    private static func validatedRawByteCount(
        scalarByteCount: Int
    ) throws(DERECDSASignatureError) -> Int {
        guard scalarByteCount > 0 else {
            throw .invalidScalarByteCount(scalarByteCount)
        }
        let (result, overflow) = scalarByteCount.multipliedReportingOverflow(by: 2)
        guard !overflow else { throw .invalidScalarByteCount(scalarByteCount) }
        return result
    }

    private static func encodeInteger(
        _ scalar: Span<UInt8>,
        scalarByteCount: Int
    ) throws(DERECDSASignatureError) -> OwnedBytes {
        var firstSignificant = 0
        while firstSignificant + 1 < scalar.count, scalar[firstSignificant] == 0 {
            firstSignificant += 1
        }
        let value = scalar.extracting(firstSignificant..<scalar.count)
        let needsSignPadding = value[0] & 0x80 != 0
        let contentCount = value.count + (needsSignPadding ? 1 : 0)
        let maximum = contentCount + Self.maximumHeaderByteCount
        do {
            var writer = try DERWriter(maximumByteCount: maximum, minimumCapacity: maximum)
            if needsSignPadding {
                var content = try ByteBuilder(
                    maximumByteCount: scalarByteCount + 1,
                    minimumCapacity: contentCount
                )
                try content.append(0)
                try content.append(value)
                let owned = content.finish()
                try writer.append(tag: integerTag, content: owned.span)
            } else {
                try writer.append(tag: integerTag, content: value)
            }
            return writer.finish()
        } catch let error as DERWriteError {
            throw .write(error)
        } catch let error as ByteError {
            throw .bytes(error)
        } catch {
            preconditionFailure("DER integer encoding has a closed typed-error surface")
        }
    }

    private static func copyCanonicalInteger(
        _ element: DERElementView,
        into output: inout ContiguousArray<UInt8>,
        offset: Int,
        scalarByteCount: Int
    ) throws(DERECDSASignatureError) {
        guard element.tag == integerTag else { throw .invalidStructure }
        let encoded = element.contentBytes
        guard !encoded.isEmpty else { throw .invalidInteger }
        let value: Span<UInt8>
        if encoded[0] == 0 {
            guard encoded.count > 1, encoded[1] & 0x80 != 0 else {
                throw .invalidInteger
            }
            value = encoded.extracting(1..<encoded.count)
        } else {
            guard encoded[0] & 0x80 == 0 else { throw .invalidInteger }
            value = encoded
        }
        guard value.count <= scalarByteCount else {
            throw .integerTooWide(maximum: scalarByteCount, actual: value.count)
        }
        let destination = offset + scalarByteCount - value.count
        var index = 0
        while index < value.count {
            output[destination + index] = value[index]
            index += 1
        }
    }
}

public enum DERECDSASignatureError: Error, Sendable, Equatable {
    case invalidScalarByteCount(Int)
    case invalidRawSignatureLength(expected: Int, actual: Int)
    case invalidStructure
    case invalidInteger
    case integerTooWide(maximum: Int, actual: Int)
    case resourceLimit(ResourceLimitError)
    case der(DERError)
    case write(DERWriteError)
    case bytes(ByteError)
}
