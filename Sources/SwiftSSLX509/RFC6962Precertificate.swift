import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto

/// Owned RFC 6962 v1 precertificate input reconstructed from a final
/// certificate containing the embedded SCT extension.
public struct RFC6962Precertificate: Sendable, Hashable {
    public let issuerKeyHash: OwnedBytes
    public let timestamps: SignedCertificateTimestampList
    public let validity: X509Validity

    private let tbsCertificate: OwnedBytes

    public init(
        reconstructing certificate: borrowing X509Certificate,
        issuerPublicKey: borrowing SubjectPublicKeyInfo
    ) throws(CertificateTransparencyError) {
        guard let extensionValue = certificate.extensions.first(where: {
            $0.objectIdentifier == Self.embeddedSCTExtensionOID
        }) else {
            throw .missingEmbeddedSCTExtension
        }
        guard !extensionValue.isCritical else {
            throw .criticalEmbeddedSCTExtension
        }

        validity = certificate.validity
        timestamps = try Self.parseEmbeddedTimestamps(extensionValue.value)
        tbsCertificate = try certificate.withTBSCertificateBytes {
            bytes throws(CertificateTransparencyError) in
            try Self.removingEmbeddedSCTExtension(from: bytes)
        }
        issuerKeyHash = try Self.makeIssuerKeyHash(issuerPublicKey)
    }

    /// Reconstructs a precertificate entry for SCTs supplied by TLS or OCSP.
    /// When the final certificate also embeds SCTs, that extension is removed;
    /// otherwise its TBSCertificate is already the poison-free signed input.
    public init(
        reconstructing certificate: borrowing X509Certificate,
        issuerPublicKey: borrowing SubjectPublicKeyInfo,
        timestamps: SignedCertificateTimestampList
    ) throws(CertificateTransparencyError) {
        validity = certificate.validity
        self.timestamps = timestamps
        let hasEmbeddedSCTs = certificate.extensions.contains(where: {
            $0.objectIdentifier == Self.embeddedSCTExtensionOID
        })
        tbsCertificate = try certificate.withTBSCertificateBytes {
            bytes throws(CertificateTransparencyError) in
            if hasEmbeddedSCTs {
                return try Self.removingEmbeddedSCTExtension(from: bytes)
            }
            return OwnedBytes(copying: bytes)
        }
        issuerKeyHash = try Self.makeIssuerKeyHash(issuerPublicKey)
    }

    private static func makeIssuerKeyHash(
        _ issuerPublicKey: borrowing SubjectPublicKeyInfo
    ) throws(CertificateTransparencyError) -> OwnedBytes {
        var digest = ContiguousArray<UInt8>(
            repeating: 0,
            count: SHA256.digestByteCount
        )
        do {
            try issuerPublicKey.withDERBytes { bytes throws(CryptoInputError) in
                var output = digest.mutableSpan
                try SHA256.hash(bytes, into: &output)
            }
        } catch {
            throw .invalidIssuerKey
        }
        return OwnedBytes(consuming: digest)
    }

    public borrowing func withTBSCertificateBytes<
        Result: ~Copyable,
        Failure: Error
    >(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(tbsCertificate.span)
    }

    private static let embeddedSCTExtensionOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 4, 1, 11_129, 2, 4, 2,
    ]

    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )

    private static let octetStringTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 4
    )

    private static let extensionsTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 3
    )

    private static func parseEmbeddedTimestamps(
        _ encoded: borrowing OwnedBytes
    ) throws(CertificateTransparencyError) -> SignedCertificateTimestampList {
        do {
            var budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: encoded.count
            )
            var cursor = DERCursor(encoded.span)
            let octets = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
            guard octets.tag == octetStringTag else {
                throw CertificateTransparencyError.invalidEmbeddedSCTExtension
            }
            return try SignedCertificateTimestampList(
                encoded: octets.contentBytes
            )
        } catch let error as CertificateTransparencyError {
            throw error
        } catch {
            throw .invalidEmbeddedSCTExtension
        }
    }

    private static func removingEmbeddedSCTExtension(
        from encodedTBS: Span<UInt8>
    ) throws(CertificateTransparencyError) -> OwnedBytes {
        do {
            var budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: encodedTBS.count
            )
            var cursor = DERCursor(encodedTBS)
            let root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
            guard root.tag == sequenceTag else {
                throw CertificateTransparencyError.invalidPrecertificate
            }

            var reconstructedBody = ContiguousArray<UInt8>()
            reconstructedBody.reserveCapacity(root.contentBytes.count)
            var body = DERCursor(root.contentBytes)
            var removed = false
            while !body.isAtEnd {
                let element = try body.readElement(using: &budget)
                if element.tag == extensionsTag {
                    guard !removed else {
                        throw CertificateTransparencyError.invalidPrecertificate
                    }
                    let replacement = try removingEmbeddedSCTExtension(
                        fromExtensions: element,
                        budget: &budget
                    )
                    if let replacement {
                        append(replacement.span, to: &reconstructedBody)
                    }
                    removed = true
                } else {
                    append(element.encodedBytes, to: &reconstructedBody)
                }
            }
            guard removed else {
                throw CertificateTransparencyError.missingEmbeddedSCTExtension
            }

            var writer = try DERWriter(
                maximumByteCount: encodedTBS.count,
                minimumCapacity: encodedTBS.count
            )
            try writer.append(tag: sequenceTag, content: reconstructedBody.span)
            return writer.finish()
        } catch let error as CertificateTransparencyError {
            throw error
        } catch {
            throw .invalidPrecertificate
        }
    }

    private static func removingEmbeddedSCTExtension(
        fromExtensions explicitElement: DERElementView,
        budget: inout ParsingBudget
    ) throws(CertificateTransparencyError) -> OwnedBytes? {
        do {
            var explicit = DERCursor(explicitElement.contentBytes)
            let sequence = try explicit.readElement(using: &budget)
            try explicit.requireFullyConsumed()
            guard sequence.tag == sequenceTag else {
                throw CertificateTransparencyError.invalidPrecertificate
            }

            var retained = ContiguousArray<UInt8>()
            retained.reserveCapacity(sequence.contentBytes.count)
            var extensions = DERCursor(sequence.contentBytes)
            var removed = false
            while !extensions.isAtEnd {
                let extensionElement = try extensions.readElement(using: &budget)
                guard extensionElement.tag == sequenceTag else {
                    throw CertificateTransparencyError.invalidPrecertificate
                }
                var extensionBody = DERCursor(extensionElement.contentBytes)
                let oidElement = try extensionBody.readElement(using: &budget)
                let oid = try DERPrimitiveCodec.decodeObjectIdentifier(
                    from: oidElement
                )
                if oid == embeddedSCTExtensionOID {
                    guard !removed else {
                        throw CertificateTransparencyError.invalidPrecertificate
                    }
                    removed = true
                } else {
                    append(extensionElement.encodedBytes, to: &retained)
                }
            }
            guard removed else {
                throw CertificateTransparencyError.missingEmbeddedSCTExtension
            }
            guard !retained.isEmpty else { return nil }

            var sequenceWriter = try DERWriter(
                maximumByteCount: explicitElement.encodedBytes.count,
                minimumCapacity: explicitElement.encodedBytes.count
            )
            try sequenceWriter.append(tag: sequenceTag, content: retained.span)
            let rebuiltSequence = sequenceWriter.finish()
            var explicitWriter = try DERWriter(
                maximumByteCount: explicitElement.encodedBytes.count,
                minimumCapacity: explicitElement.encodedBytes.count
            )
            try explicitWriter.append(
                tag: extensionsTag,
                content: rebuiltSequence.span
            )
            return explicitWriter.finish()
        } catch let error as CertificateTransparencyError {
            throw error
        } catch {
            throw .invalidPrecertificate
        }
    }

    private static func append(
        _ source: Span<UInt8>,
        to destination: inout ContiguousArray<UInt8>
    ) {
        var index = 0
        while index < source.count {
            destination.append(source[index])
            index += 1
        }
    }
}
