import SwiftSSLCore
import SwiftSSLASN1

/// A strict PFX v3 container for the project's modern PKCS #12 profile.
///
/// The profile carries one PBES2-encrypted PKCS #8 key and an ordered X.509
/// certificate chain in one data ContentInfo. Legacy PBE, unauthenticated key
/// encryption, bag attributes, and PKCS #12 MacData are rejected.
public struct PKCS12Archive: Sendable {
    public let certificateCount: Int

    private let der: OwnedBytes
    private let encryptedPrivateKeyRange: ByteRange
    private let certificateRanges: ContiguousArray<ByteRange>

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = PKCS12Archive.defaultParsingLimits
    ) throws {
        let owned = OwnedBytes(copying: encodedDER)
        let parsed = try Self.parse(owned.span, limits: limits)
        der = owned
        encryptedPrivateKeyRange = parsed.encryptedPrivateKeyRange
        certificateRanges = parsed.certificateRanges
        certificateCount = parsed.certificateRanges.count
    }

    public init(
        encryptedPrivateKeyInfo: borrowing EncryptedPrivateKeyInfo,
        certificates: [CertificateBytes],
        limits: ParsingLimits = PKCS12Archive.defaultParsingLimits
    ) throws {
        guard !certificates.isEmpty else {
            throw PKCS12ArchiveError.missingCertificates
        }
        let encoded: OwnedBytes
        do {
            encoded = try Self.encode(
                encryptedPrivateKeyInfo: encryptedPrivateKeyInfo,
                certificates: certificates
            )
        } catch let error as PKCS12ArchiveError {
            throw error
        } catch let error as DERWriteError {
            throw PKCS12ArchiveError.write(error)
        }
        let parsed = try Self.parse(encoded.span, limits: limits)
        der = encoded
        encryptedPrivateKeyRange = parsed.encryptedPrivateKeyRange
        certificateRanges = parsed.certificateRanges
        certificateCount = parsed.certificateRanges.count
    }

    public var derByteCount: Int {
        der.count
    }

    public borrowing func withDERBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes(body)
    }

    public borrowing func withEncryptedPrivateKeyInfoDER<
        Result: ~Copyable,
        Failure: Error
    >(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes { bytes throws(Failure) -> Result in
            try body(
                bytes.extracting(
                    encryptedPrivateKeyRange.offset..<encryptedPrivateKeyRange.endOffset
                )
            )
        }
    }

    public borrowing func encryptedPrivateKeyInfo() throws
        -> EncryptedPrivateKeyInfo
    {
        try withEncryptedPrivateKeyInfoDER { bytes throws -> EncryptedPrivateKeyInfo in
            try EncryptedPrivateKeyInfo(der: bytes)
        }
    }

    public borrowing func withCertificateDER<
        Result: ~Copyable,
        Failure: Error
    >(
        at index: Int,
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws -> Result {
        guard certificateRanges.indices.contains(index) else {
            throw PKCS12ArchiveError.certificateIndexOutOfBounds(
                index: index,
                count: certificateRanges.count
            )
        }
        let range = certificateRanges[index]
        return try der.withBorrowedBytes { bytes throws -> Result in
            try body(bytes.extracting(range.offset..<range.endOffset))
        }
    }

    public borrowing func certificate(at index: Int) throws
        -> CertificateBytes
    {
        try withCertificateDER(at: index) { bytes in
            CertificateBytes(copying: bytes)
        }
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 16 * 1024 * 1024,
                maximumNestingDepth: 24,
                maximumElementCount: 4_096,
                maximumExtensionCount: 1_024,
                maximumOIDBytes: 128,
                maximumStringBytes: 4 * 1024
            )
        } catch {
            preconditionFailure("PKCS12 limits are compile-time constants")
        }
    }()

    private static func parse(
        _ encodedDER: Span<UInt8>,
        limits: ParsingLimits
    ) throws -> Parsed {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: encodedDER.count
            )
        } catch let error as ResourceLimitError {
            throw PKCS12ArchiveError.resourceLimit(error)
        }

        var cursor = DERCursor(encodedDER)
        let pfx = try readElement(&cursor, budget: &budget)
        try requireFullyConsumed(cursor)
        guard pfx.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var pfxBody = DERCursor(
            pfx.contentBytes,
            baseOffset: pfx.encodedOffset + pfx.headerByteCount
        )
        let versionElement = try readElement(&pfxBody, budget: &budget)
        let version = try decodePositiveInteger(versionElement)
        guard version == 3 else {
            throw PKCS12ArchiveError.invalidVersion(version)
        }
        let authSafe = try readElement(&pfxBody, budget: &budget)
        guard pfxBody.isAtEnd else {
            throw PKCS12ArchiveError.macDataUnsupported
        }

        let authenticatedSafeRange = try parseDataContentInfo(
            authSafe,
            budget: &budget
        )
        let authenticatedSafeBytes = encodedDER.extracting(
            authenticatedSafeRange.offset..<authenticatedSafeRange.endOffset
        )
        var authenticatedSafeCursor = DERCursor(
            authenticatedSafeBytes,
            baseOffset: authenticatedSafeRange.offset
        )
        let authenticatedSafe = try readElement(
            &authenticatedSafeCursor,
            budget: &budget
        )
        try requireFullyConsumed(authenticatedSafeCursor)
        guard authenticatedSafe.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var authenticatedSafeBody = DERCursor(
            authenticatedSafe.contentBytes,
            baseOffset: authenticatedSafe.encodedOffset
                + authenticatedSafe.headerByteCount
        )
        guard !authenticatedSafeBody.isAtEnd else {
            throw PKCS12ArchiveError.unsupportedAuthenticatedSafeContent
        }
        let safeContentInfo = try readElement(
            &authenticatedSafeBody,
            budget: &budget
        )
        guard authenticatedSafeBody.isAtEnd else {
            throw PKCS12ArchiveError.multipleSafeContents
        }
        let safeContentsRange = try parseDataContentInfo(
            safeContentInfo,
            budget: &budget
        )
        return try parseSafeContents(
            source: encodedDER,
            range: safeContentsRange,
            budget: &budget
        )
    }

    private static func parseDataContentInfo(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws -> ByteRange {
        guard element.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let contentType = try readElement(&body, budget: &budget)
        guard try decodeOID(contentType) == dataOID else {
            throw PKCS12ArchiveError.unsupportedContentType
        }
        let explicitContent = try readElement(&body, budget: &budget)
        try requireFullyConsumed(body)
        guard explicitContent.tag == explicitContentTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var explicitBody = DERCursor(
            explicitContent.contentBytes,
            baseOffset: explicitContent.encodedOffset
                + explicitContent.headerByteCount
        )
        let octets = try readElement(&explicitBody, budget: &budget)
        try requireFullyConsumed(explicitBody)
        guard octets.tag == octetStringTag else {
            throw PKCS12ArchiveError.invalidStructure
        }
        return try contentRange(octets)
    }

    private static func parseSafeContents(
        source: Span<UInt8>,
        range: ByteRange,
        budget: inout ParsingBudget
    ) throws -> Parsed {
        let safeContentsBytes = source.extracting(range.offset..<range.endOffset)
        var cursor = DERCursor(safeContentsBytes, baseOffset: range.offset)
        let safeContents = try readElement(&cursor, budget: &budget)
        try requireFullyConsumed(cursor)
        guard safeContents.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var body = DERCursor(
            safeContents.contentBytes,
            baseOffset: safeContents.encodedOffset
                + safeContents.headerByteCount
        )
        var encryptedPrivateKeyRange: ByteRange?
        var certificateRanges = ContiguousArray<ByteRange>()
        while !body.isAtEnd {
            let bag = try readElement(&body, budget: &budget)
            guard bag.tag == sequenceTag else {
                throw PKCS12ArchiveError.invalidStructure
            }
            var bagBody = DERCursor(
                bag.contentBytes,
                baseOffset: bag.encodedOffset + bag.headerByteCount
            )
            let bagIdentifier = try readElement(&bagBody, budget: &budget)
            let bagOID = try decodeOID(bagIdentifier)
            let bagValue = try readElement(&bagBody, budget: &budget)
            guard bagValue.tag == explicitContentTag else {
                throw PKCS12ArchiveError.invalidStructure
            }
            guard bagBody.isAtEnd else {
                throw PKCS12ArchiveError.bagAttributesUnsupported
            }

            switch bagOID {
            case shroudedKeyBagOID:
                guard encryptedPrivateKeyRange == nil else {
                    throw PKCS12ArchiveError.multipleEncryptedPrivateKeys
                }
                encryptedPrivateKeyRange = try parseEncryptedPrivateKey(
                    bagValue,
                    budget: &budget
                )
            case certificateBagOID:
                certificateRanges.append(
                    try parseCertificateBag(bagValue, budget: &budget)
                )
            default:
                throw PKCS12ArchiveError.unsupportedBagType
            }
        }

        guard let encryptedPrivateKeyRange else {
            throw PKCS12ArchiveError.missingEncryptedPrivateKey
        }
        guard !certificateRanges.isEmpty else {
            throw PKCS12ArchiveError.missingCertificates
        }
        return Parsed(
            encryptedPrivateKeyRange: encryptedPrivateKeyRange,
            certificateRanges: certificateRanges
        )
    }

    private static func parseEncryptedPrivateKey(
        _ explicitValue: DERElementView,
        budget: inout ParsingBudget
    ) throws -> ByteRange {
        var body = DERCursor(
            explicitValue.contentBytes,
            baseOffset: explicitValue.encodedOffset
                + explicitValue.headerByteCount
        )
        let encryptedPrivateKey = try readElement(&body, budget: &budget)
        try requireFullyConsumed(body)
        guard encryptedPrivateKey.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }
        do {
            _ = try EncryptedPrivateKeyInfo(
                der: encryptedPrivateKey.encodedBytes
            )
        } catch let error as EncryptedPrivateKeyInfoError {
            throw PKCS12ArchiveError.encryptedPrivateKey(error)
        }
        return try encodedRange(encryptedPrivateKey)
    }

    private static func parseCertificateBag(
        _ explicitValue: DERElementView,
        budget: inout ParsingBudget
    ) throws -> ByteRange {
        var explicitBody = DERCursor(
            explicitValue.contentBytes,
            baseOffset: explicitValue.encodedOffset
                + explicitValue.headerByteCount
        )
        let certificateBag = try readElement(&explicitBody, budget: &budget)
        try requireFullyConsumed(explicitBody)
        guard certificateBag.tag == sequenceTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var certificateBagBody = DERCursor(
            certificateBag.contentBytes,
            baseOffset: certificateBag.encodedOffset
                + certificateBag.headerByteCount
        )
        let certificateType = try readElement(
            &certificateBagBody,
            budget: &budget
        )
        guard try decodeOID(certificateType) == x509CertificateOID else {
            throw PKCS12ArchiveError.unsupportedCertificateType
        }
        let certificateValue = try readElement(
            &certificateBagBody,
            budget: &budget
        )
        try requireFullyConsumed(certificateBagBody)
        guard certificateValue.tag == explicitContentTag else {
            throw PKCS12ArchiveError.invalidStructure
        }

        var valueBody = DERCursor(
            certificateValue.contentBytes,
            baseOffset: certificateValue.encodedOffset
                + certificateValue.headerByteCount
        )
        let certificateOctets = try readElement(&valueBody, budget: &budget)
        try requireFullyConsumed(valueBody)
        guard certificateOctets.tag == octetStringTag else {
            throw PKCS12ArchiveError.invalidStructure
        }
        do {
            _ = try X509Certificate(der: certificateOctets.contentBytes)
        } catch let error as X509CertificateError {
            throw PKCS12ArchiveError.certificate(error)
        }
        return try contentRange(certificateOctets)
    }

    private static func encode(
        encryptedPrivateKeyInfo: borrowing EncryptedPrivateKeyInfo,
        certificates: [CertificateBytes]
    ) throws -> OwnedBytes {
        var payloadByteCount = encryptedPrivateKeyInfo.derByteCount
        for certificate in certificates {
            do {
                _ = try X509Certificate(der: certificate.span)
            } catch let error as X509CertificateError {
                throw PKCS12ArchiveError.certificate(error)
            }
            let (updated, overflow) = payloadByteCount.addingReportingOverflow(
                certificate.count
            )
            guard !overflow else {
                throw PKCS12ArchiveError.sizeOverflow
            }
            payloadByteCount = updated
        }
        let (maximumByteCount, overflow) = payloadByteCount
            .addingReportingOverflow(8_192)
        guard !overflow else {
            throw PKCS12ArchiveError.sizeOverflow
        }

        var safeContentsBody = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        try encryptedPrivateKeyInfo.withDERBytes { encryptedDER throws in
            var keyBagBody = try DERWriter(
                maximumByteCount: maximumByteCount
            )
            let keyBagOID = shroudedKeyBagOID
            try keyBagBody.appendObjectIdentifier(keyBagOID.span)
            try keyBagBody.append(
                tag: explicitContentTag,
                content: encryptedDER
            )
            let keyBagContent = keyBagBody.finish()
            try safeContentsBody.append(
                tag: sequenceTag,
                content: keyBagContent.span
            )
        }

        for certificate in certificates {
            var certificateValue = try DERWriter(
                maximumByteCount: maximumByteCount
            )
            try certificateValue.append(
                tag: octetStringTag,
                content: certificate.span
            )
            let certificateValueDER = certificateValue.finish()

            var certificateBagBody = try DERWriter(
                maximumByteCount: maximumByteCount
            )
            let certificateTypeOID = x509CertificateOID
            try certificateBagBody.appendObjectIdentifier(
                certificateTypeOID.span
            )
            try certificateBagBody.append(
                tag: explicitContentTag,
                content: certificateValueDER.span
            )
            let certificateBagContent = certificateBagBody.finish()

            var certificateBag = try DERWriter(
                maximumByteCount: maximumByteCount
            )
            try certificateBag.append(
                tag: sequenceTag,
                content: certificateBagContent.span
            )
            let certificateBagDER = certificateBag.finish()

            var safeBagBody = try DERWriter(
                maximumByteCount: maximumByteCount
            )
            let bagOID = certificateBagOID
            try safeBagBody.appendObjectIdentifier(bagOID.span)
            try safeBagBody.append(
                tag: explicitContentTag,
                content: certificateBagDER.span
            )
            let safeBagContent = safeBagBody.finish()
            try safeContentsBody.append(
                tag: sequenceTag,
                content: safeBagContent.span
            )
        }

        let safeContentsContent = safeContentsBody.finish()
        var safeContents = try DERWriter(maximumByteCount: maximumByteCount)
        try safeContents.append(
            tag: sequenceTag,
            content: safeContentsContent.span
        )
        let safeContentsDER = safeContents.finish()

        let innerContentInfo = try encodeDataContentInfo(
            payload: safeContentsDER.span,
            maximumByteCount: maximumByteCount
        )
        var authenticatedSafeBody = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        try appendEncodedElement(
            innerContentInfo.span,
            to: &authenticatedSafeBody
        )
        let authenticatedSafeContent = authenticatedSafeBody.finish()
        var authenticatedSafe = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        try authenticatedSafe.append(
            tag: sequenceTag,
            content: authenticatedSafeContent.span
        )
        let authenticatedSafeDER = authenticatedSafe.finish()

        let authSafe = try encodeDataContentInfo(
            payload: authenticatedSafeDER.span,
            maximumByteCount: maximumByteCount
        )
        var pfxBody = try DERWriter(maximumByteCount: maximumByteCount)
        try pfxBody.appendPositiveInteger(3)
        try appendEncodedElement(authSafe.span, to: &pfxBody)
        let pfxContent = pfxBody.finish()
        var pfx = try DERWriter(maximumByteCount: maximumByteCount)
        try pfx.append(tag: sequenceTag, content: pfxContent.span)
        return pfx.finish()
    }

    private static func encodeDataContentInfo(
        payload: Span<UInt8>,
        maximumByteCount: Int
    ) throws -> OwnedBytes {
        var octets = try DERWriter(maximumByteCount: maximumByteCount)
        try octets.append(tag: octetStringTag, content: payload)
        let octetDER = octets.finish()

        var contentInfoBody = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        let contentTypeOID = dataOID
        try contentInfoBody.appendObjectIdentifier(contentTypeOID.span)
        try contentInfoBody.append(
            tag: explicitContentTag,
            content: octetDER.span
        )
        let contentInfoContent = contentInfoBody.finish()
        var contentInfo = try DERWriter(maximumByteCount: maximumByteCount)
        try contentInfo.append(
            tag: sequenceTag,
            content: contentInfoContent.span
        )
        return contentInfo.finish()
    }

    private static func appendEncodedElement(
        _ encoded: Span<UInt8>,
        to writer: inout DERWriter
    ) throws {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: defaultParsingLimits,
                inputByteCount: encoded.count
            )
        } catch let error as ResourceLimitError {
            throw PKCS12ArchiveError.resourceLimit(error)
        }
        var cursor = DERCursor(encoded)
        let element = try readElement(&cursor, budget: &budget)
        try requireFullyConsumed(cursor)
        try writer.append(tag: element.tag, content: element.contentBytes)
    }

    private static func contentRange(
        _ element: DERElementView
    ) throws -> ByteRange {
        do {
            return try ByteRange(
                offset: element.encodedOffset + element.headerByteCount,
                count: element.contentBytes.count
            )
        } catch let error as ByteError {
            throw PKCS12ArchiveError.invalidRange(error)
        }
    }

    private static func encodedRange(
        _ element: DERElementView
    ) throws -> ByteRange {
        do {
            return try ByteRange(
                offset: element.encodedOffset,
                count: element.encodedBytes.count
            )
        } catch let error as ByteError {
            throw PKCS12ArchiveError.invalidRange(error)
        }
    }

    @_lifetime(copy cursor)
    private static func readElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error as DERError {
            throw PKCS12ArchiveError.der(error)
        }
    }

    private static func requireFullyConsumed(_ cursor: DERCursor) throws {
        do {
            try cursor.requireFullyConsumed()
        } catch let error as DERError {
            throw PKCS12ArchiveError.der(error)
        }
    }

    private static func decodePositiveInteger(
        _ element: DERElementView
    ) throws -> UInt64 {
        do {
            return try DERPrimitiveCodec.decodePositiveInteger(from: element)
        } catch let error as DERValueError {
            throw PKCS12ArchiveError.value(error)
        }
    }

    private static func decodeOID(
        _ element: DERElementView
    ) throws -> ContiguousArray<UInt64> {
        do {
            return try DERPrimitiveCodec.decodeObjectIdentifier(from: element)
        } catch let error as DERValueError {
            throw PKCS12ArchiveError.value(error)
        }
    }

    private struct Parsed {
        let encryptedPrivateKeyRange: ByteRange
        let certificateRanges: ContiguousArray<ByteRange>
    }

    private static let dataOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 7, 1,
    ]
    private static let shroudedKeyBagOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 12, 10, 1, 2,
    ]
    private static let certificateBagOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 12, 10, 1, 3,
    ]
    private static let x509CertificateOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 9, 22, 1,
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
    private static let explicitContentTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 0
    )
}
