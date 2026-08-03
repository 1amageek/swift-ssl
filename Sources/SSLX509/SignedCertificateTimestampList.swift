import SSLCore

/// A bounded TLS-encoded RFC 6962 v1 SignedCertificateTimestampList.
public struct SignedCertificateTimestampList: Sendable, Hashable {
    public static let maximumSCTCount = 64
    public static let maximumExtensionByteCount = 4_096

    public let timestamps: ContiguousArray<SignedCertificateTimestamp>

    public init(
        encoded: Span<UInt8>
    ) throws(CertificateTransparencyError) {
        var cursor = ByteCursor(encoded)
        let declaredLength: Int
        do {
            declaredLength = Int(try cursor.readUInt16BigEndian())
        } catch let error {
            throw .byte(error)
        }
        guard declaredLength == cursor.remainingCount else {
            throw .invalidListLength
        }
        guard declaredLength > 0 else { throw .emptyList }

        let listBytes: Span<UInt8>
        do {
            listBytes = try cursor.readSpan(count: declaredLength)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .byte(error)
        }
        var list = ByteCursor(listBytes)
        var result = ContiguousArray<SignedCertificateTimestamp>()
        while !list.isAtEnd {
            guard result.count < Self.maximumSCTCount else {
                throw .tooManySCTs(limit: Self.maximumSCTCount)
            }
            let byteCount: Int
            let encodedSCT: Span<UInt8>
            do {
                byteCount = Int(try list.readUInt16BigEndian())
            } catch let error {
                throw .byte(error)
            }
            guard byteCount > 0 else {
                throw .invalidSCT
            }
            do {
                encodedSCT = try list.readSpan(count: byteCount)
            } catch let error {
                throw .byte(error)
            }
            result.append(try Self.parseSCT(encodedSCT))
        }
        guard !result.isEmpty else { throw .emptyList }
        timestamps = result
    }

    private static func parseSCT(
        _ encoded: Span<UInt8>
    ) throws(CertificateTransparencyError) -> SignedCertificateTimestamp {
        var cursor = ByteCursor(encoded)
        let version: UInt8
        let logIdentifier: Span<UInt8>
        let timestamp: UInt64
        let extensions: Span<UInt8>
        let hashAlgorithm: UInt8
        let signatureAlgorithm: UInt8
        let signature: Span<UInt8>
        do {
            version = try cursor.readByte()
            guard version == 0 else {
                throw CertificateTransparencyError.unsupportedVersion(version)
            }
            logIdentifier = try cursor.readSpan(count: 32)
            timestamp = try readUInt64(&cursor)
            let extensionByteCount = Int(try cursor.readUInt16BigEndian())
            guard extensionByteCount <= Self.maximumExtensionByteCount else {
                throw CertificateTransparencyError.invalidSCT
            }
            extensions = try cursor.readSpan(count: extensionByteCount)
            hashAlgorithm = try cursor.readByte()
            signatureAlgorithm = try cursor.readByte()
            let signatureByteCount = Int(try cursor.readUInt16BigEndian())
            guard signatureByteCount > 0 else {
                throw CertificateTransparencyError.invalidSCT
            }
            signature = try cursor.readSpan(count: signatureByteCount)
            try cursor.requireFullyConsumed()
        } catch let error as CertificateTransparencyError {
            throw error
        } catch let error as ByteError {
            throw .byte(error)
        } catch {
            throw .invalidSCT
        }
        return SignedCertificateTimestamp(
            version: version,
            logIdentifier: OwnedBytes(copying: logIdentifier),
            timestampMilliseconds: timestamp,
            extensions: OwnedBytes(copying: extensions),
            hashAlgorithm: hashAlgorithm,
            signatureAlgorithm: signatureAlgorithm,
            signature: OwnedBytes(copying: signature)
        )
    }

    private static func readUInt64(
        _ cursor: inout ByteCursor
    ) throws(ByteError) -> UInt64 {
        let bytes = try cursor.readSpan(count: 8)
        var value: UInt64 = 0
        var index = 0
        while index < 8 {
            value = (value << 8) | UInt64(bytes[index])
            index += 1
        }
        return value
    }
}
