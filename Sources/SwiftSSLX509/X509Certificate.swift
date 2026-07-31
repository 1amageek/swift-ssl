import SwiftSSLCore
import SwiftSSLASN1

public struct X509Certificate: Sendable, Hashable {
    public let version: UInt64
    public let serialNumber: OwnedBytes
    public let signatureAlgorithm: DERAlgorithmIdentifier
    public let validity: X509Validity
    public let subjectPublicKeyInfo: SubjectPublicKeyInfo

    private let der: OwnedBytes
    private let tbsRange: ByteRange
    private let signatureRange: ByteRange

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = X509Certificate.defaultParsingLimits
    ) throws(X509CertificateError) {
        let owned = OwnedBytes(copying: encodedDER)
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: limits, inputByteCount: owned.count)
        } catch let error {
            throw .resourceLimit(error)
        }

        var cursor = DERCursor(owned.span)
        let certificate: DERElementView
        do {
            certificate = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard certificate.tag == sequenceTag else {
            throw .invalidStructure
        }
        var certificateBody = DERCursor(
            certificate.contentBytes,
            baseOffset: certificate.encodedOffset + certificate.headerByteCount
        )
        let tbsElement: DERElementView
        let signatureAlgorithmElement: DERElementView
        let signatureValueElement: DERElementView
        do {
            tbsElement = try certificateBody.readElement(using: &budget)
            signatureAlgorithmElement = try certificateBody.readElement(using: &budget)
            signatureValueElement = try certificateBody.readElement(using: &budget)
            try certificateBody.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        guard tbsElement.tag == sequenceTag else {
            throw .invalidStructure
        }

        var tbs = DERCursor(
            tbsElement.contentBytes,
            baseOffset: tbsElement.encodedOffset + tbsElement.headerByteCount
        )
        var version: UInt64 = 0
        if !tbs.isAtEnd {
            let first = try Self.tryReadElement(&tbs, budget: &budget)
            if first.tag == DERTag(tagClass: .contextSpecific, isConstructed: true, number: 0) {
                var versionCursor = DERCursor(
                    first.contentBytes,
                    baseOffset: first.encodedOffset + first.headerByteCount
                )
                let versionElement = try Self.tryReadElement(&versionCursor, budget: &budget)
                do {
                    version = try DERPrimitiveCodec.decodePositiveInteger(from: versionElement)
                } catch let error {
                    throw .value(error)
                }
                do {
                    try versionCursor.requireFullyConsumed()
                } catch let error {
                    throw .der(error)
                }
                guard version <= 2 else {
                    throw .invalidVersion(version)
                }
            } else {
                version = 0
                tbs = DERCursor(
                    tbsElement.contentBytes,
                    baseOffset: tbsElement.encodedOffset + tbsElement.headerByteCount
                )
            }
        }

        let serialElement = try Self.tryReadElement(&tbs, budget: &budget)
        let tbsSignatureElement = try Self.tryReadElement(&tbs, budget: &budget)
        let issuerElement = try Self.tryReadElement(&tbs, budget: &budget)
        let validityElement = try Self.tryReadElement(&tbs, budget: &budget)
        let subjectElement = try Self.tryReadElement(&tbs, budget: &budget)
        let spkiElement = try Self.tryReadElement(&tbs, budget: &budget)
        _ = issuerElement
        _ = subjectElement

        let serial: OwnedBytes
        do {
            let serialSpan = serialElement.contentBytes
            guard !serialSpan.isEmpty, serialSpan[0] & 0x80 == 0 else {
                throw X509CertificateError.invalidSerialNumber
            }
            serial = OwnedBytes(copying: serialSpan)
        }

        let tbsSignature: DERAlgorithmIdentifier
        do {
            tbsSignature = try DERAlgorithmIdentifier.parse(from: tbsSignatureElement, using: &budget)
        } catch let error {
            throw .algorithm(error)
        }
        let validity = try Self.parseValidity(validityElement, budget: &budget)
        let spkiRange: ByteRange
        do {
            spkiRange = try ByteRange(
                offset: spkiElement.encodedOffset,
                count: spkiElement.encodedBytes.count
            )
        } catch let error {
            throw .invalidRange(error)
        }
        let spkiDER: Span<UInt8>
        do {
            spkiDER = try owned.span(in: spkiRange)
        } catch let error {
            throw .invalidRange(error)
        }
        let spki: SubjectPublicKeyInfo
        do {
            spki = try SubjectPublicKeyInfo(der: spkiDER)
        } catch let error {
            throw .publicKeyInfo(error)
        }

        var sawExtensions = false
        while !tbs.isAtEnd {
            let optionalElement = try Self.tryReadElement(&tbs, budget: &budget)
            guard optionalElement.tag.tagClass == DERTagClass.contextSpecific else {
                throw .invalidStructure
            }
            switch optionalElement.tag.number {
            case 1, 2:
                throw .invalidStructure
            case 3:
                guard optionalElement.tag.isConstructed, !sawExtensions else {
                    throw .duplicateOptionalField
                }
                sawExtensions = true
            default:
                throw .invalidStructure
            }
        }

        let outerSignatureAlgorithm: DERAlgorithmIdentifier
        do {
            outerSignatureAlgorithm = try DERAlgorithmIdentifier.parse(
                from: signatureAlgorithmElement,
                using: &budget
            )
        } catch let error {
            throw .algorithm(error)
        }
        guard outerSignatureAlgorithm == tbsSignature else {
            throw .invalidStructure
        }
        let signatureBits: DERBitString
        do {
            signatureBits = try DERPrimitiveCodec.decodeBitString(from: signatureValueElement)
        } catch let error {
            throw .value(error)
        }
        guard signatureBits.unusedBitCount == 0 else {
            throw .invalidSignatureValue
        }
        let signatureRange: ByteRange
        do {
            signatureRange = try ByteRange(
                offset: signatureValueElement.encodedOffset + signatureValueElement.headerByteCount + 1,
                count: signatureBits.bytes.count
            )
        } catch let error {
            throw .invalidRange(error)
        }
        do {
            try tbs.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }

        self.version = version
        self.serialNumber = serial
        self.signatureAlgorithm = outerSignatureAlgorithm
        self.validity = validity
        self.subjectPublicKeyInfo = spki
        let tbsRange: ByteRange
        do {
            tbsRange = try Self.makeRange(tbsElement)
        } catch let error {
            throw .invalidRange(error)
        }
        self.der = owned
        self.tbsRange = tbsRange
        self.signatureRange = signatureRange
    }

    public borrowing func withTBSCertificateBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: tbsRange)
        } catch {
            preconditionFailure("X509Certificate stores a validated TBS range")
        }
        return try body(bytes)
    }

    public borrowing func withSignatureBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: signatureRange)
        } catch {
            preconditionFailure("X509Certificate stores a validated signature range")
        }
        return try body(bytes)
    }

    public static let defaultParsingLimits: ParsingLimits = {
        do {
            return try ParsingLimits(
                maximumInputBytes: 16 * 1024 * 1024,
                maximumNestingDepth: 32,
                maximumElementCount: 512,
                maximumExtensionCount: 64,
                maximumOIDBytes: 128,
                maximumStringBytes: 16 * 1024
            )
        } catch {
            preconditionFailure("X509Certificate limits are compile-time constants")
        }
    }()

    private static func makeRange(_ element: DERElementView) throws(ByteError) -> ByteRange {
        try ByteRange(offset: element.encodedOffset, count: element.encodedBytes.count)
    }

    private static func parseValidity(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509CertificateError) -> X509Validity {
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard element.tag == sequenceTag else {
            throw .invalidValidity
        }
        var cursor = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let notBefore = try Self.tryReadElement(&cursor, budget: &budget)
        let notAfter = try Self.tryReadElement(&cursor, budget: &budget)
        do {
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        return try X509Validity.decode(
            notBefore: notBefore.contentBytes,
            notAfter: notAfter.contentBytes
        )
    }

    @_lifetime(copy cursor)
    private static func tryReadElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws(X509CertificateError) -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error {
            throw .der(error)
        }
    }
}
