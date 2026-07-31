import SwiftSSLCore
import SwiftSSLASN1
import SwiftSSLCrypto

public struct X509Certificate: Sendable, Hashable {
    public let version: UInt64
    public let serialNumber: OwnedBytes
    public let signatureAlgorithm: DERAlgorithmIdentifier
    public let validity: X509Validity
    public let subjectPublicKeyInfo: SubjectPublicKeyInfo
    public let extensions: ContiguousArray<X509Extension>

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
            guard serialSpan.count == 1 || serialSpan[0] != 0 || serialSpan[1] & 0x80 != 0 else {
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
        var extensions = ContiguousArray<X509Extension>()
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
                do {
                    extensions = try Self.parseExtensions(optionalElement, budget: &budget)
                } catch let error {
                    throw .extensions(error)
                }
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
        self.extensions = extensions
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

    /// Verifies the certificate signature for the supported signature algorithms.
    public borrowing func verifySignature() throws(X509CertificateError) {
        if signatureAlgorithm.objectIdentifier == [1, 3, 101, 112] {
            guard signatureAlgorithm.parameters == .absent,
                  subjectPublicKeyInfo.algorithm == .ed25519,
                  subjectPublicKeyInfo.algorithmIdentifier.parameters == .absent else {
                throw .unsupportedSignatureAlgorithm
            }

            let valid: Bool
            do {
                valid = try withTBSCertificateBytes { tbs throws(CryptoInputError) in
                    try withSignatureBytes { signature throws(CryptoInputError) in
                        try subjectPublicKeyInfo.withPublicKeyBytes { publicKey throws(CryptoInputError) in
                            try Ed25519.verify(
                                signature: signature,
                                message: tbs,
                                publicKey: publicKey
                            )
                        }
                    }
                }
            } catch {
                throw .signatureVerificationFailed
            }
            guard valid else {
                throw .signatureVerificationFailed
            }
            return
        }

        // FIXME(INCOMPLETE_IMPLEMENTATION): This X.509 branch is vector- and
        // certificate-tested, but its P-256 arithmetic still requires the
        // constant-time and differential release gates. The current call
        // path is validation-only and must not be selected by TLS until those
        // gates pass.
        let digest: ContiguousArray<UInt8>
        switch Array(signatureAlgorithm.objectIdentifier) {
        case [1, 2, 840, 10045, 4, 3, 2]:
            guard signatureAlgorithm.parameters == .absent,
                  subjectPublicKeyInfo.algorithm == .ecPublicKey(curve: .prime256v1),
                  subjectPublicKeyInfo.algorithmIdentifier.parameters
                    == .objectIdentifier([1, 2, 840, 10045, 3, 1, 7]) else {
                throw .unsupportedSignatureAlgorithm
            }
            digest = try hashSHA256(tbs: self)
        case [1, 2, 840, 10045, 4, 3, 3]:
            guard signatureAlgorithm.parameters == .absent,
                  subjectPublicKeyInfo.algorithm == .ecPublicKey(curve: .prime256v1),
                  subjectPublicKeyInfo.algorithmIdentifier.parameters
                    == .objectIdentifier([1, 2, 840, 10045, 3, 1, 7]) else {
                throw .unsupportedSignatureAlgorithm
            }
            digest = try hashSHA384(tbs: self)
        case [1, 2, 840, 10045, 4, 3, 4]:
            guard signatureAlgorithm.parameters == .absent,
                  subjectPublicKeyInfo.algorithm == .ecPublicKey(curve: .prime256v1),
                  subjectPublicKeyInfo.algorithmIdentifier.parameters
                    == .objectIdentifier([1, 2, 840, 10045, 3, 1, 7]) else {
                throw .unsupportedSignatureAlgorithm
            }
            digest = try hashSHA512(tbs: self)
        default:
            throw .unsupportedSignatureAlgorithm
        }

        let rawSignature: ContiguousArray<UInt8>
        do {
            rawSignature = try withSignatureBytes { signature in
                try Self.decodeECDSASignature(signature)
            }
        } catch {
            throw .signatureVerificationFailed
        }

        let valid: Bool
        do {
            valid = try withPublicKeyAndDigest(rawSignature: rawSignature, digest: digest)
        } catch {
            throw .signatureVerificationFailed
        }
        guard valid else {
            throw .signatureVerificationFailed
        }
    }

    private borrowing func withPublicKeyAndDigest(
        rawSignature: ContiguousArray<UInt8>,
        digest: ContiguousArray<UInt8>
    ) throws(CryptoInputError) -> Bool {
        try subjectPublicKeyInfo.withPublicKeyBytes { publicKey throws(CryptoInputError) in
            let key = try P256PublicKey(bytes: publicKey)
            return try P256ECDSA.verify(
                signature: rawSignature.span,
                messageHash: digest.span,
                publicKey: key
            )
        }
    }

    private borrowing func hashSHA256(
        tbs: borrowing X509Certificate
    ) throws(X509CertificateError) -> ContiguousArray<UInt8> {
        var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
        do {
            try tbs.withTBSCertificateBytes { bytes throws(CryptoInputError) in
                var output = digest.mutableSpan
                try SHA256.hash(bytes, into: &output)
            }
        } catch {
            throw .signatureVerificationFailed
        }
        return digest
    }

    private borrowing func hashSHA384(
        tbs: borrowing X509Certificate
    ) throws(X509CertificateError) -> ContiguousArray<UInt8> {
        var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
        do {
            try tbs.withTBSCertificateBytes { bytes throws(CryptoInputError) in
                var output = digest.mutableSpan
                try SHA384.hash(bytes, into: &output)
            }
        } catch {
            throw .signatureVerificationFailed
        }
        return digest
    }

    private borrowing func hashSHA512(
        tbs: borrowing X509Certificate
    ) throws(X509CertificateError) -> ContiguousArray<UInt8> {
        var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
        do {
            try tbs.withTBSCertificateBytes { bytes throws(CryptoInputError) in
                var output = digest.mutableSpan
                try SHA512.hash(bytes, into: &output)
            }
        } catch {
            throw .signatureVerificationFailed
        }
        return digest
    }

    private static func decodeECDSASignature(
        _ signature: Span<UInt8>
    ) throws(X509CertificateError) -> ContiguousArray<UInt8> {
        guard signature.count <= 256 else {
            throw .signatureVerificationFailed
        }
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(limits: Self.defaultParsingLimits, inputByteCount: signature.count)
        } catch {
            throw .signatureVerificationFailed
        }
        var cursor = DERCursor(signature)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .signatureVerificationFailed
        }
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        guard root.tag == sequenceTag else {
            throw .signatureVerificationFailed
        }
        var body = DERCursor(root.contentBytes)
        let rElement: DERElementView
        let sElement: DERElementView
        do {
            rElement = try body.readElement(using: &budget)
            sElement = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch {
            throw .signatureVerificationFailed
        }

        var raw = ContiguousArray<UInt8>(repeating: 0, count: P256ECDSA.signatureByteCount)
        do {
            try Self.copyECDSAComponent(rElement, into: &raw, offset: 0)
            try Self.copyECDSAComponent(sElement, into: &raw, offset: 32)
        } catch {
            throw .signatureVerificationFailed
        }
        return raw
    }

    private static func copyECDSAComponent(
        _ element: DERElementView,
        into output: inout ContiguousArray<UInt8>,
        offset: Int
    ) throws(X509CertificateError) {
        let integerTag = DERTag(tagClass: .universal, isConstructed: false, number: 2)
        guard element.tag == integerTag else {
            throw .signatureVerificationFailed
        }
        let component = element.contentBytes
        guard !component.isEmpty else {
            throw .signatureVerificationFailed
        }
        if component.count > 1, component[0] == 0 {
            guard component[1] & 0x80 != 0 else {
                throw .signatureVerificationFailed
            }
        } else {
            guard component[0] & 0x80 == 0 else {
                throw .signatureVerificationFailed
            }
        }
        let value = component[0] == 0 ? component.extracting(1..<component.count) : component
        guard !value.isEmpty, value.count <= 32 else {
            throw .signatureVerificationFailed
        }
        let destinationOffset = offset + 32 - value.count
        var index = 0
        while index < value.count {
            output[destinationOffset + index] = value[index]
            index += 1
        }
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

    private static func parseExtensions(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509ExtensionError) -> ContiguousArray<X509Extension> {
        let sequenceTag = DERTag(tagClass: .universal, isConstructed: true, number: 16)
        var explicit = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let sequence: DERElementView
        do {
            sequence = try explicit.readElement(using: &budget)
            try explicit.requireFullyConsumed()
        } catch let error {
            throw Self.mapExtensionDER(error)
        }
        guard sequence.tag == sequenceTag else { throw .invalidStructure }
        guard !sequence.contentBytes.isEmpty else { throw .invalidStructure }
        var cursor = DERCursor(
            sequence.contentBytes,
            baseOffset: sequence.encodedOffset + sequence.headerByteCount
        )
        var result = ContiguousArray<X509Extension>()
        while !cursor.isAtEnd {
            let extensionElement: DERElementView
            do {
                extensionElement = try cursor.readElement(using: &budget)
            } catch let error {
                throw Self.mapExtensionDER(error)
            }
            guard extensionElement.tag == sequenceTag else { throw .invalidStructure }
            do {
                try budget.consumeExtension()
            } catch let error {
                throw .resourceLimit(error)
            }
            var body = DERCursor(
                extensionElement.contentBytes,
                baseOffset: extensionElement.encodedOffset + extensionElement.headerByteCount
            )
            let oidElement: DERElementView
            do {
                oidElement = try body.readElement(using: &budget)
            } catch let error {
                throw Self.mapExtensionDER(error)
            }
            let oid: ContiguousArray<UInt64>
            do {
                try budget.requireOIDByteCount(oidElement.contentBytes.count)
                oid = try DERPrimitiveCodec.decodeObjectIdentifier(from: oidElement)
            } catch let error as ResourceLimitError {
                throw .resourceLimit(error)
            } catch let error as DERValueError {
                throw .value(error)
            } catch {
                throw .invalidStructure
            }
            for existing in result where existing.objectIdentifier == oid {
                throw .duplicateObjectIdentifier
            }
            var critical = false
            if !body.isAtEnd {
                let next = try Self.readExtensionElement(&body, budget: &budget)
                let booleanTag = DERTag(tagClass: .universal, isConstructed: false, number: 1)
                if next.tag == booleanTag {
                    do {
                        critical = try DERPrimitiveCodec.decodeBoolean(from: next)
                    } catch let error {
                        throw .value(error)
                    }
                    guard critical else { throw .invalidStructure }
                } else {
                    guard next.tag.number == 4,
                          next.tag.tagClass == .universal,
                          !next.tag.isConstructed else {
                        throw .invalidStructure
                    }
                    result.append(X509Extension(objectIdentifier: oid, isCritical: false, value: OwnedBytes(copying: next.contentBytes)))
                    do {
                        try body.requireFullyConsumed()
                    } catch let error {
                        throw Self.mapExtensionDER(error)
                    }
                    continue
                }
            }
            let valueElement = try Self.readExtensionElement(&body, budget: &budget)
            guard valueElement.tag == DERTag(tagClass: .universal, isConstructed: false, number: 4) else {
                throw .invalidStructure
            }
            do {
                try body.requireFullyConsumed()
            } catch let error {
                throw Self.mapExtensionDER(error)
            }
            result.append(X509Extension(objectIdentifier: oid, isCritical: critical, value: OwnedBytes(copying: valueElement.contentBytes)))
        }
        return result
    }

    @_lifetime(copy cursor)
    private static func readExtensionElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws(X509ExtensionError) -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error {
            throw Self.mapExtensionDER(error)
        }
    }

    private static func mapExtensionDER(_ error: DERError) -> X509ExtensionError {
        if case let .resourceLimit(resourceLimit) = error {
            return .resourceLimit(resourceLimit)
        }
        return .der(error)
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
