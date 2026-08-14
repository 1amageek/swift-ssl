import SSLCore
import SSLASN1

extension SubjectPublicKeyInfo {
    /// Encodes a canonical P-256 SubjectPublicKeyInfo from an SEC 1 point.
    public static func encodeP256(
        uncompressedPoint: Span<UInt8>
    ) throws(SubjectPublicKeyInfoEncodingError) -> OwnedBytes {
        guard uncompressedPoint.count == 65, uncompressedPoint[0] == 0x04 else {
            throw .invalidKeyLength(expected: 65, actual: uncompressedPoint.count)
        }
        return try encode(
            algorithmOID: [1, 2, 840, 10045, 2, 1],
            parameterOID: [1, 2, 840, 10045, 3, 1, 7],
            publicKey: uncompressedPoint
        )
    }

    /// Encodes a canonical P-384 SubjectPublicKeyInfo from an SEC 1 point.
    public static func encodeP384(
        uncompressedPoint: Span<UInt8>
    ) throws(SubjectPublicKeyInfoEncodingError) -> OwnedBytes {
        guard uncompressedPoint.count == 97, uncompressedPoint[0] == 0x04 else {
            throw .invalidKeyLength(expected: 97, actual: uncompressedPoint.count)
        }
        return try encode(
            algorithmOID: [1, 2, 840, 10045, 2, 1],
            parameterOID: [1, 3, 132, 0, 34],
            publicKey: uncompressedPoint
        )
    }

    /// Encodes a canonical RFC 8410 Ed25519 SubjectPublicKeyInfo.
    public static func encodeEd25519(
        publicKey: Span<UInt8>
    ) throws(SubjectPublicKeyInfoEncodingError) -> OwnedBytes {
        guard publicKey.count == 32 else {
            throw .invalidKeyLength(expected: 32, actual: publicKey.count)
        }
        return try encode(
            algorithmOID: [1, 3, 101, 112],
            parameterOID: nil,
            publicKey: publicKey
        )
    }

    private static func encode(
        algorithmOID: ContiguousArray<UInt64>,
        parameterOID: ContiguousArray<UInt64>?,
        publicKey: Span<UInt8>
    ) throws(SubjectPublicKeyInfoEncodingError) -> OwnedBytes {
        do {
            let algorithmOID = try encodedOID(algorithmOID)
            var algorithmContent = try ByteBuilder(maximumByteCount: 128)
            try algorithmContent.append(algorithmOID.span)
            if let parameterOID {
                let encodedParameter = try encodedOID(parameterOID)
                try algorithmContent.append(encodedParameter.span)
            }
            let algorithm = try encodedElement(
                tag: DERTag(tagClass: .universal, isConstructed: true, number: 16),
                content: algorithmContent.finish().span,
                maximumByteCount: 160
            )

            var bitStringContent = try ByteBuilder(
                maximumByteCount: publicKey.count + 1,
                minimumCapacity: publicKey.count + 1
            )
            try bitStringContent.append(0)
            try bitStringContent.append(publicKey)
            let bitString = try encodedElement(
                tag: DERTag(tagClass: .universal, isConstructed: false, number: 3),
                content: bitStringContent.finish().span,
                maximumByteCount: publicKey.count + 8
            )

            var rootContent = try ByteBuilder(maximumByteCount: 320)
            try rootContent.append(algorithm.span)
            try rootContent.append(bitString.span)
            return try encodedElement(
                tag: DERTag(tagClass: .universal, isConstructed: true, number: 16),
                content: rootContent.finish().span,
                maximumByteCount: 336
            )
        } catch let error as DERWriteError {
            throw .der(error)
        } catch let error as ByteError {
            throw .bytes(error)
        } catch {
            preconditionFailure("SubjectPublicKeyInfo encoding has a closed error surface")
        }
    }

    private static func encodedOID(
        _ arcs: ContiguousArray<UInt64>
    ) throws(DERWriteError) -> OwnedBytes {
        var writer = try DERWriter(maximumByteCount: 128, minimumCapacity: 16)
        try writer.appendObjectIdentifier(arcs.span)
        return writer.finish()
    }

    private static func encodedElement(
        tag: DERTag,
        content: Span<UInt8>,
        maximumByteCount: Int
    ) throws(DERWriteError) -> OwnedBytes {
        var writer = try DERWriter(
            maximumByteCount: maximumByteCount,
            minimumCapacity: content.count + 2
        )
        try writer.append(tag: tag, content: content)
        return writer.finish()
    }
}

public enum SubjectPublicKeyInfoEncodingError: Error, Sendable, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case der(DERWriteError)
    case bytes(ByteError)
}
