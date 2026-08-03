import SSLASN1
import SSLCore

/// An immutable, strict-DER X.509 certificate revocation list.
///
/// The object owns one contiguous DER buffer. Signed bytes, signature bytes,
/// and revoked serial numbers are retained as checked ranges into that owner;
/// verification exposes only scoped borrows and does not materialize payload
/// copies.
public struct X509CertificateRevocationList: Sendable, Hashable {
    public let issuerName: OwnedBytes
    public let thisUpdate: VerificationInstant
    public let nextUpdate: VerificationInstant?
    public let signatureAlgorithm: X509SignatureAlgorithm

    private let der: OwnedBytes
    private let tbsRange: ByteRange
    private let signatureRange: ByteRange
    private let revokedCertificates: ContiguousArray<RevokedCertificate>

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = X509Certificate.defaultParsingLimits
    ) throws(X509CertificateRevocationListError) {
        let owned = OwnedBytes(copying: encodedDER)
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: owned.count
            )
        } catch let error {
            throw .resourceLimit(error)
        }
        var cursor = DERCursor(owned.span)
        let certificateList: DERElementView
        do {
            certificateList = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
        guard certificateList.tag == Self.sequenceTag else {
            throw .invalidStructure
        }
        var body = DERCursor(
            certificateList.contentBytes,
            baseOffset: certificateList.encodedOffset
                + certificateList.headerByteCount
        )
        let tbs = try Self.readElement(&body, budget: &budget)
        let outerAlgorithmElement = try Self.readElement(
            &body,
            budget: &budget
        )
        let signatureElement = try Self.readElement(&body, budget: &budget)
        try Self.requireFullyConsumed(body)
        guard tbs.tag == Self.sequenceTag,
              signatureElement.tag == Self.bitStringTag else {
            throw .invalidStructure
        }

        let outerAlgorithm: X509SignatureAlgorithm
        do {
            outerAlgorithm = try X509SignatureAlgorithm(
                element: outerAlgorithmElement,
                budget: &budget
            )
        } catch let error {
            throw .signatureAlgorithm(error)
        }
        let signature: DERBitString
        do {
            signature = try DERPrimitiveCodec.decodeBitString(
                from: signatureElement
            )
        } catch let error {
            throw .value(error)
        }
        guard signature.unusedBitCount == 0 else {
            throw .invalidStructure
        }

        var tbsBody = DERCursor(
            tbs.contentBytes,
            baseOffset: tbs.encodedOffset + tbs.headerByteCount
        )
        var version: UInt64 = 0
        var first = try Self.readElement(&tbsBody, budget: &budget)
        if first.tag == Self.integerTag {
            do {
                version = try DERPrimitiveCodec.decodePositiveInteger(
                    from: first
                )
            } catch let error {
                throw .value(error)
            }
            guard version == 1 else { throw .invalidVersion }
            first = try Self.readElement(&tbsBody, budget: &budget)
        }

        let tbsAlgorithmElement = first
        let tbsAlgorithm: X509SignatureAlgorithm
        do {
            tbsAlgorithm = try X509SignatureAlgorithm(
                element: tbsAlgorithmElement,
                budget: &budget
            )
        } catch let error {
            throw .signatureAlgorithm(error)
        }
        guard tbsAlgorithm == outerAlgorithm else {
            throw .mismatchedSignatureAlgorithm
        }

        let issuer = try Self.readElement(&tbsBody, budget: &budget)
        guard issuer.tag == Self.sequenceTag else { throw .invalidStructure }
        issuerName = OwnedBytes(copying: issuer.encodedBytes)

        let thisUpdateElement = try Self.readElement(
            &tbsBody,
            budget: &budget
        )
        thisUpdate = try Self.decodeTime(thisUpdateElement)

        var parsedNextUpdate: VerificationInstant?
        var parsedRevoked = ContiguousArray<RevokedCertificate>()
        var sawExtensions = false
        if !tbsBody.isAtEnd {
            let candidate = try Self.readElement(&tbsBody, budget: &budget)
            if Self.isTime(candidate) {
                parsedNextUpdate = try Self.decodeTime(candidate)
                if !tbsBody.isAtEnd {
                    let next = try Self.readElement(&tbsBody, budget: &budget)
                    if next.tag == Self.sequenceTag {
                        parsedRevoked = try Self.parseRevokedCertificates(
                            next,
                            budget: &budget
                        )
                    } else {
                        try Self.parseCRLExtensions(
                            next,
                            version: version,
                            budget: &budget
                        )
                        sawExtensions = true
                    }
                }
            } else if candidate.tag == Self.sequenceTag {
                parsedRevoked = try Self.parseRevokedCertificates(
                    candidate,
                    budget: &budget
                )
            } else {
                try Self.parseCRLExtensions(
                    candidate,
                    version: version,
                    budget: &budget
                )
                sawExtensions = true
            }
        }
        if !tbsBody.isAtEnd {
            let extensions = try Self.readElement(&tbsBody, budget: &budget)
            try Self.parseCRLExtensions(
                extensions,
                version: version,
                budget: &budget
            )
            sawExtensions = true
        }
        try Self.requireFullyConsumed(tbsBody)
        if sawExtensions, version != 1 { throw .invalidVersion }
        if let parsedNextUpdate, parsedNextUpdate < thisUpdate {
            throw .invalidTime
        }
        try Self.requireUniqueSerials(parsedRevoked, in: owned)

        do {
            tbsRange = try ByteRange(
                offset: tbs.encodedOffset,
                count: tbs.encodedBytes.count
            )
            signatureRange = try ByteRange(
                offset: signatureElement.encodedOffset
                    + signatureElement.headerByteCount + 1,
                count: signature.bytes.count
            )
        } catch {
            throw .invalidStructure
        }
        nextUpdate = parsedNextUpdate
        signatureAlgorithm = outerAlgorithm
        revokedCertificates = parsedRevoked
        der = owned
    }

    public borrowing func evaluate(
        certificate: borrowing X509Certificate,
        issuer: borrowing X509Certificate,
        at instant: VerificationInstant,
        policy: X509CRLValidationPolicy = X509CRLValidationPolicy()
    ) throws(X509CertificateRevocationListError) -> X509RevocationStatus {
        guard issuerName == issuer.subjectName,
              certificate.issuerName == issuer.subjectName else {
            throw .issuerMismatch
        }
        try Self.requireCRLSigningUsage(issuer)
        try validateFreshness(at: instant, policy: policy)

        do {
            try withSignedBytes {
                signedBytes throws(X509SignatureVerificationError) in
                try withSignatureBytes {
                    signature throws(X509SignatureVerificationError) in
                    try X509SignedPayloadVerifier.verify(
                        signedBytes: signedBytes,
                        signature: signature,
                        algorithm: signatureAlgorithm,
                        using: issuer.subjectPublicKeyInfo
                    )
                }
            }
        } catch let error {
            throw .signature(error)
        }

        var index = 0
        while index < revokedCertificates.count {
            let record = revokedCertificates[index]
            let serial: Span<UInt8>
            do {
                serial = try der.span(in: record.serialRange)
            } catch {
                preconditionFailure("CRL stores validated serial ranges")
            }
            if ConstantTime.equal(serial, certificate.serialNumber.span),
               record.revocationDate <= instant {
                return .revoked(at: record.revocationDate)
            }
            index += 1
        }
        return .good
    }

    public borrowing func withSignedBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: tbsRange)
        } catch {
            preconditionFailure("CRL stores a validated signed-data range")
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
            preconditionFailure("CRL stores a validated signature range")
        }
        return try body(bytes)
    }

    private borrowing func validateFreshness(
        at instant: VerificationInstant,
        policy: X509CRLValidationPolicy
    ) throws(X509CertificateRevocationListError) {
        let futureLimit = Self.addingSeconds(
            policy.maximumClockSkewSeconds,
            to: instant
        )
        guard thisUpdate <= futureLimit else { throw .producedInFuture }
        if let nextUpdate {
            let expirationLimit = Self.addingSeconds(
                policy.maximumClockSkewSeconds,
                to: nextUpdate
            )
            guard instant <= expirationLimit else { throw .expired }
            return
        }
        guard !policy.requireNextUpdate else { throw .missingNextUpdate }
        let expiration = Self.addingSeconds(
            policy.maximumAgeWithoutNextUpdateSeconds,
            to: thisUpdate
        )
        let expirationLimit = Self.addingSeconds(
            policy.maximumClockSkewSeconds,
            to: expiration
        )
        guard instant <= expirationLimit else { throw .expired }
    }

    private static func parseRevokedCertificates(
        _ sequence: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509CertificateRevocationListError)
        -> ContiguousArray<RevokedCertificate>
    {
        guard sequence.tag == sequenceTag,
              !sequence.contentBytes.isEmpty else {
            throw .invalidStructure
        }
        var body = DERCursor(
            sequence.contentBytes,
            baseOffset: sequence.encodedOffset + sequence.headerByteCount
        )
        var records = ContiguousArray<RevokedCertificate>()
        while !body.isAtEnd {
            let entry = try readElement(&body, budget: &budget)
            guard entry.tag == sequenceTag else { throw .invalidStructure }
            var entryBody = DERCursor(
                entry.contentBytes,
                baseOffset: entry.encodedOffset + entry.headerByteCount
            )
            let serial = try readElement(&entryBody, budget: &budget)
            guard serial.tag == integerTag else {
                throw .invalidSerialNumber
            }
            try requireCanonicalSerial(serial)
            let revocationDate = try decodeTime(
                readElement(&entryBody, budget: &budget)
            )
            if !entryBody.isAtEnd {
                let extensions = try readElement(
                    &entryBody,
                    budget: &budget
                )
                try parseEntryExtensions(extensions, budget: &budget)
            }
            try requireFullyConsumed(entryBody)
            let range: ByteRange
            do {
                range = try ByteRange(
                    offset: serial.encodedOffset + serial.headerByteCount,
                    count: serial.contentBytes.count
                )
            } catch {
                throw .invalidSerialNumber
            }
            records.append(RevokedCertificate(
                serialRange: range,
                revocationDate: revocationDate
            ))
        }
        return records
    }

    private static func parseEntryExtensions(
        _ sequence: DERElementView,
        budget: inout ParsingBudget
    ) throws(X509CertificateRevocationListError) {
        try parseExtensions(
            sequence,
            explicitTag: nil,
            budget: &budget,
            allowedCriticalObjectIdentifiers: [reasonCodeOID]
        )
    }

    private static func parseCRLExtensions(
        _ explicit: DERElementView,
        version: UInt64,
        budget: inout ParsingBudget
    ) throws(X509CertificateRevocationListError) {
        guard version == 1,
              explicit.tag == crlExtensionsTag else {
            throw .invalidStructure
        }
        try parseExtensions(
            explicit,
            explicitTag: crlExtensionsTag,
            budget: &budget,
            allowedCriticalObjectIdentifiers: []
        )
    }

    private static func parseExtensions(
        _ container: DERElementView,
        explicitTag: DERTag?,
        budget: inout ParsingBudget,
        allowedCriticalObjectIdentifiers:
            ContiguousArray<ContiguousArray<UInt64>>
    ) throws(X509CertificateRevocationListError) {
        let sequence: DERElementView
        if let explicitTag {
            guard container.tag == explicitTag else {
                throw .invalidStructure
            }
            var explicitBody = DERCursor(container.contentBytes)
            sequence = try readElement(&explicitBody, budget: &budget)
            try requireFullyConsumed(explicitBody)
        } else {
            sequence = container
        }
        guard sequence.tag == sequenceTag,
              !sequence.contentBytes.isEmpty else {
            throw .invalidStructure
        }
        var body = DERCursor(sequence.contentBytes)
        var seen = ContiguousArray<ContiguousArray<UInt64>>()
        while !body.isAtEnd {
            let extensionElement = try readElement(&body, budget: &budget)
            guard extensionElement.tag == sequenceTag else {
                throw .invalidStructure
            }
            var extensionBody = DERCursor(extensionElement.contentBytes)
            let oidElement = try readElement(
                &extensionBody,
                budget: &budget
            )
            let oid: ContiguousArray<UInt64>
            do {
                oid = try DERPrimitiveCodec.decodeObjectIdentifier(
                    from: oidElement
                )
            } catch let error {
                throw .value(error)
            }
            guard !seen.contains(oid) else { throw .invalidStructure }
            seen.append(oid)
            var critical = false
            var value = try readElement(&extensionBody, budget: &budget)
            if value.tag == booleanTag {
                do {
                    critical = try DERPrimitiveCodec.decodeBoolean(from: value)
                } catch let error {
                    throw .value(error)
                }
                guard critical else { throw .invalidStructure }
                value = try readElement(&extensionBody, budget: &budget)
            }
            guard value.tag == octetStringTag else {
                throw .invalidStructure
            }
            try requireFullyConsumed(extensionBody)
            if oid == deltaCRLIndicatorOID { throw .unsupportedDeltaCRL }
            if oid == issuingDistributionPointOID {
                throw .unsupportedIndirectCRL
            }
            if critical,
               !allowedCriticalObjectIdentifiers.contains(oid) {
                throw .unsupportedCriticalExtension(oid)
            }
        }
    }

    private static func requireCanonicalSerial(
        _ element: DERElementView
    ) throws(X509CertificateRevocationListError) {
        let bytes = element.contentBytes
        guard !bytes.isEmpty,
              bytes[0] & 0x80 == 0,
              !(bytes.count > 1
                && bytes[0] == 0
                && bytes[1] & 0x80 == 0) else {
            throw .invalidSerialNumber
        }
    }

    private static func requireUniqueSerials(
        _ records: borrowing ContiguousArray<RevokedCertificate>,
        in owner: borrowing OwnedBytes
    ) throws(X509CertificateRevocationListError) {
        var left = 0
        while left < records.count {
            let leftSerial: Span<UInt8>
            do {
                leftSerial = try owner.span(in: records[left].serialRange)
            } catch {
                throw .invalidSerialNumber
            }
            var right = left + 1
            while right < records.count {
                let rightSerial: Span<UInt8>
                do {
                    rightSerial = try owner.span(
                        in: records[right].serialRange
                    )
                } catch {
                    throw .invalidSerialNumber
                }
                if ConstantTime.equal(leftSerial, rightSerial) {
                    throw .duplicateSerialNumber
                }
                right += 1
            }
            left += 1
        }
    }

    private static func requireCRLSigningUsage(
        _ issuer: borrowing X509Certificate
    ) throws(X509CertificateRevocationListError) {
        guard let keyUsage = issuer.extensions.first(where: {
            $0.objectIdentifier == keyUsageOID
        }) else { return }
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: keyUsage.value.count
            )
        } catch {
            throw .issuerKeyUsageViolation
        }
        var cursor = DERCursor(keyUsage.value.span)
        let element: DERElementView
        do {
            element = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .issuerKeyUsageViolation
        }
        let bits: DERBitString
        do {
            bits = try DERPrimitiveCodec.decodeBitString(from: element)
        } catch {
            throw .issuerKeyUsageViolation
        }
        guard !bits.bytes.isEmpty, bits.bytes.span[0] & 0x02 != 0 else {
            throw .issuerKeyUsageViolation
        }
    }

    private static func decodeTime(
        _ element: DERElementView
    ) throws(X509CertificateRevocationListError) -> VerificationInstant {
        guard (element.tag == utcTimeTag && element.contentBytes.count == 13)
                || (element.tag == generalizedTimeTag
                    && element.contentBytes.count == 15),
              let decoded = X509Validity.decodeTime(element.contentBytes) else {
            throw .invalidTime
        }
        return decoded.instant
    }

    private static func isTime(_ element: DERElementView) -> Bool {
        element.tag == utcTimeTag || element.tag == generalizedTimeTag
    }

    private static func addingSeconds(
        _ seconds: Int64,
        to instant: VerificationInstant
    ) -> VerificationInstant {
        let result = instant.secondsSinceUnixEpoch.addingReportingOverflow(
            seconds
        )
        let value = result.overflow ? Int64.max : result.partialValue
        do {
            return try VerificationInstant(
                secondsSinceUnixEpoch: value,
                nanoseconds: instant.nanoseconds
            )
        } catch {
            preconditionFailure("existing nanoseconds are always valid")
        }
    }

    @_lifetime(copy cursor)
    private static func readElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws(X509CertificateRevocationListError) -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error {
            throw .der(error)
        }
    }

    private static func requireFullyConsumed(
        _ cursor: DERCursor
    ) throws(X509CertificateRevocationListError) {
        do {
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
    }

    private struct RevokedCertificate: Sendable, Hashable {
        let serialRange: ByteRange
        let revocationDate: VerificationInstant
    }

    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let integerTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 2
    )
    private static let booleanTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 1
    )
    private static let bitStringTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 3
    )
    private static let octetStringTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 4
    )
    private static let utcTimeTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 23
    )
    private static let generalizedTimeTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 24
    )
    private static let crlExtensionsTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 0
    )
    private static let keyUsageOID: ContiguousArray<UInt64> = [2, 5, 29, 15]
    private static let reasonCodeOID: ContiguousArray<UInt64> = [2, 5, 29, 21]
    private static let deltaCRLIndicatorOID: ContiguousArray<UInt64> = [
        2, 5, 29, 27,
    ]
    private static let issuingDistributionPointOID: ContiguousArray<UInt64> = [
        2, 5, 29, 28,
    ]
}
