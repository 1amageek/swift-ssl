import SSLCore
import SSLASN1

/// A CMS SignedData certificate-only container with no signer information.
///
/// This type implements the certificate distribution subset commonly carried
/// by `.p7b` files. It does not expose a generic CMS signing API.
public struct CMSCertificateCollection: Sendable {
    public let certificateCount: Int

    private let der: OwnedBytes
    private let certificateRanges: ContiguousArray<ByteRange>

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = CMSCertificateCollection.defaultParsingLimits
    ) throws {
        let owned = OwnedBytes(copying: encodedDER)
        let ranges = try Self.parse(owned.span, limits: limits)
        der = owned
        certificateRanges = ranges
        certificateCount = ranges.count
    }

    public init(
        certificates: [CertificateBytes],
        limits: ParsingLimits = CMSCertificateCollection.defaultParsingLimits
    ) throws {
        guard !certificates.isEmpty else {
            throw CMSCertificateCollectionError.emptyCertificateCollection
        }
        let encoded: OwnedBytes
        do {
            encoded = try Self.encode(certificates: certificates)
        } catch let error as CMSCertificateCollectionError {
            throw error
        } catch let error as DERWriteError {
            throw CMSCertificateCollectionError.write(error)
        }
        let ranges = try Self.parse(encoded.span, limits: limits)
        der = encoded
        certificateRanges = ranges
        certificateCount = ranges.count
    }

    public borrowing func withDERBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try der.withBorrowedBytes(body)
    }

    public borrowing func withCertificateDER<
        Result: ~Copyable,
        Failure: Error
    >(
        at index: Int,
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws -> Result {
        guard certificateRanges.indices.contains(index) else {
            throw CMSCertificateCollectionError.certificateIndexOutOfBounds(
                index: index,
                count: certificateRanges.count
            )
        }
        let range = certificateRanges[index]
        return try der.withBorrowedBytes {
            (bytes: Span<UInt8>) throws -> Result in
            try body(bytes.extracting(range.offset..<range.endOffset))
        }
    }

    public borrowing func certificate(
        at index: Int
    ) throws -> CertificateBytes {
        try withCertificateDER(at: index) { bytes in
            CertificateBytes(copying: bytes)
        }
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 16 * 1024 * 1024,
                maximumNestingDepth: 16,
                maximumElementCount: 4_096,
                maximumExtensionCount: 1_024,
                maximumOIDBytes: 128,
                maximumStringBytes: 4 * 1024
            )
        } catch {
            preconditionFailure(
                "CMS certificate limits are compile-time constants"
            )
        }
    }()

    private static func parse(
        _ encodedDER: Span<UInt8>,
        limits: ParsingLimits
    ) throws -> ContiguousArray<ByteRange> {
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: encodedDER.count
            )
        } catch let error {
            throw CMSCertificateCollectionError.resourceLimit(error)
        }

        var rootCursor = DERCursor(encodedDER)
        let contentInfo = try readElement(&rootCursor, budget: &budget)
        try requireFullyConsumed(rootCursor)
        guard contentInfo.tag == sequenceTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }

        var contentInfoBody = DERCursor(
            contentInfo.contentBytes,
            baseOffset: contentInfo.encodedOffset + contentInfo.headerByteCount
        )
        let contentType = try readElement(&contentInfoBody, budget: &budget)
        guard try decodeOID(contentType) == signedDataOID else {
            throw CMSCertificateCollectionError.unsupportedContentType
        }
        let explicitContent = try readElement(&contentInfoBody, budget: &budget)
        try requireFullyConsumed(contentInfoBody)
        guard explicitContent.tag == explicitContentTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }

        var explicitBody = DERCursor(
            explicitContent.contentBytes,
            baseOffset: explicitContent.encodedOffset
                + explicitContent.headerByteCount
        )
        let signedData = try readElement(&explicitBody, budget: &budget)
        try requireFullyConsumed(explicitBody)
        guard signedData.tag == sequenceTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }

        var signedDataBody = DERCursor(
            signedData.contentBytes,
            baseOffset: signedData.encodedOffset + signedData.headerByteCount
        )
        let versionElement = try readElement(
            &signedDataBody,
            budget: &budget
        )
        let version = try decodePositiveInteger(versionElement)
        guard version == 1 else {
            throw CMSCertificateCollectionError.invalidVersion(version)
        }

        let digestAlgorithms = try readElement(
            &signedDataBody,
            budget: &budget
        )
        guard digestAlgorithms.tag == setTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }
        guard digestAlgorithms.contentBytes.isEmpty else {
            throw CMSCertificateCollectionError.nonEmptyDigestAlgorithms
        }

        let encapsulatedContent = try readElement(
            &signedDataBody,
            budget: &budget
        )
        try validateEncapsulatedContent(encapsulatedContent, budget: &budget)

        let certificates = try readElement(&signedDataBody, budget: &budget)
        guard certificates.tag == certificateSetTag else {
            throw CMSCertificateCollectionError.missingCertificates
        }
        let ranges = try parseCertificates(
            certificates,
            budget: &budget,
            source: encodedDER
        )

        let signerInfos = try readElement(&signedDataBody, budget: &budget)
        try requireFullyConsumed(signedDataBody)
        guard signerInfos.tag == setTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }
        guard signerInfos.contentBytes.isEmpty else {
            throw CMSCertificateCollectionError.nonEmptySignerInfos
        }
        return ranges
    }

    private static func validateEncapsulatedContent(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws {
        guard element.tag == sequenceTag else {
            throw CMSCertificateCollectionError.invalidStructure
        }
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let contentType = try readElement(&body, budget: &budget)
        guard try decodeOID(contentType) == dataOID else {
            throw CMSCertificateCollectionError.unsupportedEncapsulatedContentType
        }
        try requireFullyConsumed(body)
    }

    private static func parseCertificates(
        _ element: DERElementView,
        budget: inout ParsingBudget,
        source: Span<UInt8>
    ) throws -> ContiguousArray<ByteRange> {
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        var ranges = ContiguousArray<ByteRange>()
        var previousRange: ByteRange?
        while !body.isAtEnd {
            let certificate = try readElement(&body, budget: &budget)
            guard certificate.tag == sequenceTag else {
                throw CMSCertificateCollectionError.unsupportedCertificateChoice
            }
            let range: ByteRange
            do {
                range = try ByteRange(
                    offset: certificate.encodedOffset,
                    count: certificate.encodedBytes.count
                )
            } catch let error {
                throw CMSCertificateCollectionError.invalidRange(error)
            }
            if let previousRange {
                let previous = source.extracting(
                    previousRange.offset..<previousRange.endOffset
                )
                if lexicographicallyPrecedes(certificate.encodedBytes, previous) {
                    throw CMSCertificateCollectionError.nonCanonicalCertificateOrder
                }
            }
            do {
                _ = try X509Certificate(der: certificate.encodedBytes)
            } catch let error {
                throw CMSCertificateCollectionError.certificate(error)
            }
            ranges.append(range)
            previousRange = range
        }
        guard !ranges.isEmpty else {
            throw CMSCertificateCollectionError.emptyCertificateCollection
        }
        return ranges
    }

    private static func encode(
        certificates: [CertificateBytes]
    ) throws -> OwnedBytes {
        var totalCertificateBytes = 0
        for certificate in certificates {
            let (updated, overflow) = totalCertificateBytes
                .addingReportingOverflow(certificate.count)
            guard !overflow else {
                throw CMSCertificateCollectionError.sizeOverflow
            }
            totalCertificateBytes = updated
            do {
                _ = try X509Certificate(der: certificate.span)
            } catch let error {
                throw CMSCertificateCollectionError.certificate(error)
            }
        }
        let (maximumByteCount, overflow) = totalCertificateBytes
            .addingReportingOverflow(2_048)
        guard !overflow else {
            throw CMSCertificateCollectionError.sizeOverflow
        }

        var order = Array(certificates.indices)
        order.sort {
            certificatePrecedes(certificates[$0], certificates[$1])
        }

        var certificateBody = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        for index in order {
            try appendCertificate(certificates[index], to: &certificateBody)
        }
        let certificateContent = certificateBody.finish()

        let dataOID = Self.dataOID
        var encapsulatedContentBody = try DERWriter(maximumByteCount: 64)
        try encapsulatedContentBody.appendObjectIdentifier(dataOID.span)
        let encapsulatedContent = encapsulatedContentBody.finish()

        let empty = ContiguousArray<UInt8>()
        var signedDataBody = try DERWriter(maximumByteCount: maximumByteCount)
        try signedDataBody.appendPositiveInteger(1)
        try signedDataBody.append(tag: setTag, content: empty.span)
        try signedDataBody.append(
            tag: sequenceTag,
            content: encapsulatedContent.span
        )
        try signedDataBody.append(
            tag: certificateSetTag,
            content: certificateContent.span
        )
        try signedDataBody.append(tag: setTag, content: empty.span)
        let signedDataContent = signedDataBody.finish()

        var signedData = try DERWriter(maximumByteCount: maximumByteCount)
        try signedData.append(tag: sequenceTag, content: signedDataContent.span)
        let signedDataDER = signedData.finish()

        var explicitContent = try DERWriter(
            maximumByteCount: maximumByteCount
        )
        try explicitContent.append(
            tag: explicitContentTag,
            content: signedDataDER.span
        )
        let explicitContentDER = explicitContent.finish()

        let signedDataOID = Self.signedDataOID
        var contentInfoBody = try DERWriter(maximumByteCount: maximumByteCount)
        try contentInfoBody.appendObjectIdentifier(signedDataOID.span)
        var explicitCursor = DERCursor(explicitContentDER.span)
        var explicitBudget = try makeEncodingBudget(
            inputByteCount: explicitContentDER.count
        )
        let explicitElement = try readElement(
            &explicitCursor,
            budget: &explicitBudget
        )
        try contentInfoBody.append(
            tag: explicitElement.tag,
            content: explicitElement.contentBytes
        )
        let contentInfoContent = contentInfoBody.finish()

        var root = try DERWriter(maximumByteCount: maximumByteCount)
        try root.append(tag: sequenceTag, content: contentInfoContent.span)
        return root.finish()
    }

    private static func makeEncodingBudget(
        inputByteCount: Int
    ) throws -> ParsingBudget {
        do {
            return try ParsingBudget(
                limits: defaultParsingLimits,
                inputByteCount: inputByteCount
            )
        } catch let error {
            throw CMSCertificateCollectionError.resourceLimit(error)
        }
    }

    private static func appendCertificate(
        _ certificate: borrowing CertificateBytes,
        to writer: inout DERWriter
    ) throws {
        var cursor = DERCursor(certificate.span)
        var budget = try makeEncodingBudget(
            inputByteCount: certificate.count
        )
        let element: DERElementView
        do {
            element = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw CMSCertificateCollectionError.der(error)
        }
        try writer.append(tag: element.tag, content: element.contentBytes)
    }

    @_lifetime(copy cursor)
    private static func readElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error {
            throw CMSCertificateCollectionError.der(error)
        }
    }

    private static func requireFullyConsumed(
        _ cursor: DERCursor
    ) throws {
        do {
            try cursor.requireFullyConsumed()
        } catch let error {
            throw CMSCertificateCollectionError.der(error)
        }
    }

    private static func decodePositiveInteger(
        _ element: DERElementView
    ) throws -> UInt64 {
        do {
            return try DERPrimitiveCodec.decodePositiveInteger(from: element)
        } catch let error {
            throw CMSCertificateCollectionError.value(error)
        }
    }

    private static func decodeOID(
        _ element: DERElementView
    ) throws -> ContiguousArray<UInt64> {
        do {
            return try DERPrimitiveCodec.decodeObjectIdentifier(from: element)
        } catch let error {
            throw CMSCertificateCollectionError.value(error)
        }
    }

    private static func lexicographicallyPrecedes(
        _ lhs: Span<UInt8>,
        _ rhs: Span<UInt8>
    ) -> Bool {
        let sharedCount = min(lhs.count, rhs.count)
        var index = 0
        while index < sharedCount {
            if lhs[index] != rhs[index] {
                return lhs[index] < rhs[index]
            }
            index += 1
        }
        return lhs.count < rhs.count
    }

    private static func certificatePrecedes(
        _ lhs: borrowing CertificateBytes,
        _ rhs: borrowing CertificateBytes
    ) -> Bool {
        lexicographicallyPrecedes(lhs.span, rhs.span)
    }

    private static let signedDataOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 7, 2,
    ]
    private static let dataOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 7, 1,
    ]
    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let setTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 17
    )
    private static let explicitContentTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 0
    )
    private static let certificateSetTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 0
    )
}
