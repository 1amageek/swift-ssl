import SSLASN1
import SSLCore
import SSLCrypto

/// A strict RFC 6960 BasicOCSPResponse owner and verifier.
///
/// Fetching is intentionally outside this type. The response owns one DER
/// buffer, authenticates the borrowed ResponseData bytes, authorizes either
/// the issuer, a directly issued OCSPSigning responder, or a caller-trusted
/// responder, and then evaluates one matching CertID.
public struct OCSPResponse: Sendable, Hashable {
    public let producedAt: VerificationInstant
    public let signatureAlgorithm: X509SignatureAlgorithm

    private let der: OwnedBytes
    private let responseDataRange: ByteRange
    private let signatureRange: ByteRange
    private let responderIdentifier: ResponderIdentifier
    private let responses: ContiguousArray<SingleResponse>
    private let includedCertificates: ContiguousArray<X509Certificate>
    private let nonce: OwnedBytes?
    private let responseSignedCertificateTimestamps:
        SignedCertificateTimestampList?

    public init(
        der encodedDER: Span<UInt8>,
        limits: ParsingLimits = X509Certificate.defaultParsingLimits
    ) throws(OCSPResponseError) {
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
        let outer = try Self.readElement(&cursor, budget: &budget)
        try Self.requireFullyConsumed(cursor)
        guard outer.tag == Self.sequenceTag else { throw .invalidStructure }
        var outerBody = DERCursor(
            outer.contentBytes,
            baseOffset: outer.encodedOffset + outer.headerByteCount
        )
        let statusElement = try Self.readElement(
            &outerBody,
            budget: &budget
        )
        let status = try Self.decodeEnumerated(statusElement)
        guard status == 0 else { throw .unsuccessfulResponse(status) }
        let responseBytes = try Self.readElement(&outerBody, budget: &budget)
        try Self.requireFullyConsumed(outerBody)
        guard responseBytes.tag == Self.responseBytesTag else {
            throw .invalidStructure
        }
        var responseBytesBody = DERCursor(
            responseBytes.contentBytes,
            baseOffset: responseBytes.encodedOffset
                + responseBytes.headerByteCount
        )
        let responseBytesSequence = try Self.readElement(
            &responseBytesBody,
            budget: &budget
        )
        try Self.requireFullyConsumed(responseBytesBody)
        guard responseBytesSequence.tag == Self.sequenceTag else {
            throw .invalidStructure
        }
        var responseBody = DERCursor(
            responseBytesSequence.contentBytes,
            baseOffset: responseBytesSequence.encodedOffset
                + responseBytesSequence.headerByteCount
        )
        let responseTypeElement = try Self.readElement(
            &responseBody,
            budget: &budget
        )
        let responseType: ContiguousArray<UInt64>
        do {
            responseType = try DERPrimitiveCodec.decodeObjectIdentifier(
                from: responseTypeElement
            )
        } catch let error {
            throw .value(error)
        }
        guard responseType == Self.basicResponseOID else {
            throw .unsupportedResponseType
        }
        let responseOctets = try Self.readElement(
            &responseBody,
            budget: &budget
        )
        try Self.requireFullyConsumed(responseBody)
        guard responseOctets.tag == Self.octetStringTag else {
            throw .invalidStructure
        }

        var basicCursor = DERCursor(
            responseOctets.contentBytes,
            baseOffset: responseOctets.encodedOffset
                + responseOctets.headerByteCount
        )
        let basic = try Self.readElement(&basicCursor, budget: &budget)
        try Self.requireFullyConsumed(basicCursor)
        guard basic.tag == Self.sequenceTag else { throw .invalidStructure }
        var basicBody = DERCursor(
            basic.contentBytes,
            baseOffset: basic.encodedOffset + basic.headerByteCount
        )
        let responseData = try Self.readElement(&basicBody, budget: &budget)
        let algorithmElement = try Self.readElement(
            &basicBody,
            budget: &budget
        )
        let signatureElement = try Self.readElement(
            &basicBody,
            budget: &budget
        )
        guard responseData.tag == Self.sequenceTag,
              signatureElement.tag == Self.bitStringTag else {
            throw .invalidStructure
        }
        let signatureBits: DERBitString
        do {
            signatureBits = try DERPrimitiveCodec.decodeBitString(
                from: signatureElement
            )
        } catch let error {
            throw .value(error)
        }
        guard signatureBits.unusedBitCount == 0 else {
            throw .invalidStructure
        }
        do {
            signatureAlgorithm = try X509SignatureAlgorithm(
                element: algorithmElement,
                budget: &budget
            )
        } catch let error {
            throw .signatureAlgorithm(error)
        }

        var certificates = ContiguousArray<X509Certificate>()
        if !basicBody.isAtEnd {
            let certificateContainer = try Self.readElement(
                &basicBody,
                budget: &budget
            )
            guard certificateContainer.tag == Self.certificatesTag else {
                throw .invalidStructure
            }
            var explicitBody = DERCursor(certificateContainer.contentBytes)
            let sequence = try Self.readElement(
                &explicitBody,
                budget: &budget
            )
            try Self.requireFullyConsumed(explicitBody)
            guard sequence.tag == Self.sequenceTag,
                  !sequence.contentBytes.isEmpty else {
                throw .invalidStructure
            }
            var certificateBody = DERCursor(sequence.contentBytes)
            while !certificateBody.isAtEnd {
                let certificateElement = try Self.readElement(
                    &certificateBody,
                    budget: &budget
                )
                let certificate: X509Certificate
                do {
                    certificate = try X509Certificate(
                        der: certificateElement.encodedBytes,
                        limits: limits
                    )
                } catch let error {
                    throw .certificate(error)
                }
                guard !certificates.contains(certificate) else {
                    throw .invalidStructure
                }
                certificates.append(certificate)
            }
        }
        try Self.requireFullyConsumed(basicBody)

        let parsedResponseData = try Self.parseResponseData(
            responseData,
            budget: &budget
        )
        do {
            responseDataRange = try ByteRange(
                offset: responseData.encodedOffset,
                count: responseData.encodedBytes.count
            )
            signatureRange = try ByteRange(
                offset: signatureElement.encodedOffset
                    + signatureElement.headerByteCount + 1,
                count: signatureBits.bytes.count
            )
        } catch {
            throw .invalidStructure
        }
        producedAt = parsedResponseData.producedAt
        responderIdentifier = parsedResponseData.responderIdentifier
        responses = parsedResponseData.responses
        nonce = parsedResponseData.nonce
        responseSignedCertificateTimestamps =
            parsedResponseData.signedCertificateTimestamps
        includedCertificates = certificates
        der = owned
    }

    public borrowing func evaluate(
        certificate: borrowing X509Certificate,
        issuer: borrowing X509Certificate,
        at instant: VerificationInstant,
        expectedNonce: Span<UInt8>? = nil,
        trustedResponders: ContiguousArray<X509Certificate> = [],
        policy: OCSPValidationPolicy = OCSPValidationPolicy()
    ) throws(OCSPResponseError) -> X509RevocationStatus {
        try validateNonce(expectedNonce)
        let signerKey = try authorizedResponderKey(
            issuer: issuer,
            trustedResponders: trustedResponders,
            at: instant
        )
        do {
            try withResponseDataBytes {
                responseData throws(X509SignatureVerificationError) in
                try withSignatureBytes {
                    signature throws(X509SignatureVerificationError) in
                    try X509SignedPayloadVerifier.verify(
                        signedBytes: responseData,
                        signature: signature,
                        algorithm: signatureAlgorithm,
                        using: signerKey
                    )
                }
            }
        } catch let error {
            throw .signature(error)
        }

        let futureLimit = Self.addingSeconds(
            policy.maximumClockSkewSeconds,
            to: instant
        )
        guard producedAt <= futureLimit else { throw .producedInFuture }

        var match: SingleResponse?
        var index = 0
        while index < responses.count {
            let candidate = responses[index]
            if try candidate.matches(certificate: certificate, issuer: issuer) {
                guard match == nil else {
                    throw .duplicateCertificateStatus
                }
                match = candidate
            }
            index += 1
        }
        guard let match else { throw .matchingCertificateStatusNotFound }
        try Self.validateFreshness(
            match,
            at: instant,
            policy: policy
        )
        switch match.status {
        case .good:
            return .good
        case .revoked(let revocationTime):
            return revocationTime <= instant
                ? .revoked(at: revocationTime)
                : .good
        case .unknown:
            throw .unknownCertificateStatus
        }
    }

    public borrowing func withResponseDataBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let bytes: Span<UInt8>
        do {
            bytes = try der.span(in: responseDataRange)
        } catch {
            preconditionFailure("OCSP response stores a validated data range")
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
            preconditionFailure("OCSP response stores a validated signature range")
        }
        return try body(bytes)
    }

    /// Returns authenticated SCT evidence associated with one certificate.
    /// Call this only after `evaluate` succeeds for the same certificate and
    /// issuer; a response-level list and a matching SingleResponse list are
    /// rejected together because their aggregation policy must be explicit.
    public borrowing func signedCertificateTimestamps(
        certificate: borrowing X509Certificate,
        issuer: borrowing X509Certificate
    ) throws(OCSPResponseError) -> SignedCertificateTimestampList? {
        var match: SingleResponse?
        var index = 0
        while index < responses.count {
            let candidate = responses[index]
            if try candidate.matches(certificate: certificate, issuer: issuer) {
                guard match == nil else {
                    throw .duplicateCertificateStatus
                }
                match = candidate
            }
            index += 1
        }
        guard let match else { throw .matchingCertificateStatusNotFound }
        guard responseSignedCertificateTimestamps == nil
                || match.signedCertificateTimestamps == nil else {
            throw .invalidStructure
        }
        return match.signedCertificateTimestamps
            ?? responseSignedCertificateTimestamps
    }

    private borrowing func validateNonce(
        _ expectedNonce: Span<UInt8>?
    ) throws(OCSPResponseError) {
        guard let expectedNonce else { return }
        guard let nonce else { throw .missingNonce }
        guard ConstantTime.equal(expectedNonce, nonce.span) else {
            throw .nonceMismatch
        }
    }

    private borrowing func authorizedResponderKey(
        issuer: borrowing X509Certificate,
        trustedResponders: borrowing ContiguousArray<X509Certificate>,
        at instant: VerificationInstant
    ) throws(OCSPResponseError) -> SubjectPublicKeyInfo {
        if responderIdentifier.matches(issuer) {
            return issuer.subjectPublicKeyInfo
        }

        var index = 0
        while index < includedCertificates.count {
            let candidate = includedCertificates[index]
            if responderIdentifier.matches(candidate) {
                guard candidate.validity.contains(instant) else {
                    throw .responderCertificateNotValid
                }
                guard candidate.issuerName == issuer.subjectName else {
                    throw .unauthorizedResponder
                }
                do {
                    try candidate.verifySignature(
                        using: issuer.subjectPublicKeyInfo
                    )
                } catch let error {
                    throw .certificate(error)
                }
                try Self.requireOCSPSigningPurpose(candidate)
                return candidate.subjectPublicKeyInfo
            }
            index += 1
        }

        index = 0
        while index < trustedResponders.count {
            let candidate = trustedResponders[index]
            if responderIdentifier.matches(candidate) {
                guard candidate.validity.contains(instant) else {
                    throw .responderCertificateNotValid
                }
                try Self.requireOCSPSigningPurpose(candidate)
                return candidate.subjectPublicKeyInfo
            }
            index += 1
        }
        throw .unauthorizedResponder
    }

    private static func parseResponseData(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> ParsedResponseData {
        var body = DERCursor(
            element.contentBytes,
            baseOffset: element.encodedOffset + element.headerByteCount
        )
        let responderID = try readElement(&body, budget: &budget)
        guard responderID.tag != versionTag else { throw .invalidVersion }
        let responderIdentifier = try parseResponderIdentifier(
            responderID,
            budget: &budget
        )
        let producedAt = try decodeGeneralizedTime(
            readElement(&body, budget: &budget)
        )
        let responseSequence = try readElement(&body, budget: &budget)
        guard responseSequence.tag == sequenceTag,
              !responseSequence.contentBytes.isEmpty else {
            throw .invalidStructure
        }
        var responseBody = DERCursor(
            responseSequence.contentBytes,
            baseOffset: responseSequence.encodedOffset
                + responseSequence.headerByteCount
        )
        var responses = ContiguousArray<SingleResponse>()
        while !responseBody.isAtEnd {
            responses.append(try parseSingleResponse(
                readElement(&responseBody, budget: &budget),
                budget: &budget
            ))
        }
        var parsedExtensions = ParsedExtensions()
        if !body.isAtEnd {
            parsedExtensions = try parseExtensions(
                readElement(&body, budget: &budget),
                expectedTag: responseExtensionsTag,
                budget: &budget
            )
        }
        try requireFullyConsumed(body)
        return ParsedResponseData(
            responderIdentifier: responderIdentifier,
            producedAt: producedAt,
            responses: responses,
            nonce: parsedExtensions.nonce,
            signedCertificateTimestamps:
                parsedExtensions.signedCertificateTimestamps
        )
    }

    private static func parseResponderIdentifier(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> ResponderIdentifier {
        if element.tag == responderByNameTag {
            var body = DERCursor(element.contentBytes)
            let name = try readElement(&body, budget: &budget)
            try requireFullyConsumed(body)
            guard name.tag == sequenceTag else { throw .invalidStructure }
            return .name(OwnedBytes(copying: name.encodedBytes))
        }
        guard element.tag == responderByKeyTag,
              element.contentBytes.count == OCSPIdentifierHash.digestByteCount
        else {
            throw .invalidStructure
        }
        return .keyHash(OwnedBytes(copying: element.contentBytes))
    }

    private static func parseSingleResponse(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> SingleResponse {
        guard element.tag == sequenceTag else { throw .invalidStructure }
        var body = DERCursor(element.contentBytes)
        let certificateIdentifier = try parseCertificateIdentifier(
            readElement(&body, budget: &budget),
            budget: &budget
        )
        let status = try parseCertificateStatus(
            readElement(&body, budget: &budget),
            budget: &budget
        )
        let thisUpdate = try decodeGeneralizedTime(
            readElement(&body, budget: &budget)
        )
        var nextUpdate: VerificationInstant?
        var parsedExtensions = ParsedExtensions()
        if !body.isAtEnd {
            let optional = try readElement(&body, budget: &budget)
            if optional.tag == nextUpdateTag {
                var nextUpdateBody = DERCursor(optional.contentBytes)
                nextUpdate = try decodeGeneralizedTime(
                    readElement(&nextUpdateBody, budget: &budget)
                )
                try requireFullyConsumed(nextUpdateBody)
                if !body.isAtEnd {
                    parsedExtensions = try parseExtensions(
                        readElement(&body, budget: &budget),
                        expectedTag: singleExtensionsTag,
                        budget: &budget
                    )
                }
            } else {
                parsedExtensions = try parseExtensions(
                    optional,
                    expectedTag: singleExtensionsTag,
                    budget: &budget
                )
            }
        }
        try requireFullyConsumed(body)
        if let nextUpdate, nextUpdate < thisUpdate { throw .invalidTime }
        return SingleResponse(
            certificateIdentifier: certificateIdentifier,
            status: status,
            thisUpdate: thisUpdate,
            nextUpdate: nextUpdate,
            signedCertificateTimestamps:
                parsedExtensions.signedCertificateTimestamps
        )
    }

    private static func parseCertificateIdentifier(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> CertificateIdentifier {
        guard element.tag == sequenceTag else { throw .invalidStructure }
        var body = DERCursor(element.contentBytes)
        let hashAlgorithmElement = try readElement(&body, budget: &budget)
        let hashAlgorithmIdentifier: DERAlgorithmIdentifier
        do {
            hashAlgorithmIdentifier = try DERAlgorithmIdentifier.parse(
                from: hashAlgorithmElement,
                using: &budget
            )
        } catch {
            throw .unsupportedIdentifierHash
        }
        guard hashAlgorithmIdentifier.parameters == .absent
                || hashAlgorithmIdentifier.parameters == .null else {
            throw .unsupportedIdentifierHash
        }
        let hashAlgorithm: IdentifierHashAlgorithm
        switch hashAlgorithmIdentifier.objectIdentifier {
        case sha1OID: hashAlgorithm = .sha1
        case sha256OID: hashAlgorithm = .sha256
        default: throw .unsupportedIdentifierHash
        }
        let issuerNameHash = try readElement(&body, budget: &budget)
        let issuerKeyHash = try readElement(&body, budget: &budget)
        let serialNumber = try readElement(&body, budget: &budget)
        try requireFullyConsumed(body)
        guard issuerNameHash.tag == octetStringTag,
              issuerKeyHash.tag == octetStringTag,
              issuerNameHash.contentBytes.count == hashAlgorithm.digestByteCount,
              issuerKeyHash.contentBytes.count == hashAlgorithm.digestByteCount
        else {
            throw .invalidIdentifierHashLength
        }
        try requireCanonicalSerial(serialNumber)
        return CertificateIdentifier(
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: OwnedBytes(copying: issuerNameHash.contentBytes),
            issuerKeyHash: OwnedBytes(copying: issuerKeyHash.contentBytes),
            serialNumber: OwnedBytes(copying: serialNumber.contentBytes)
        )
    }

    private static func parseCertificateStatus(
        _ element: DERElementView,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> CertificateStatus {
        if element.tag == goodStatusTag {
            guard element.contentBytes.isEmpty else { throw .invalidStructure }
            return .good
        }
        if element.tag == unknownStatusTag {
            guard element.contentBytes.isEmpty else { throw .invalidStructure }
            return .unknown
        }
        guard element.tag == revokedStatusTag else { throw .invalidStructure }
        var body = DERCursor(element.contentBytes)
        let revocationTime = try decodeGeneralizedTime(
            readElement(&body, budget: &budget)
        )
        if !body.isAtEnd {
            let reason = try readElement(&body, budget: &budget)
            guard reason.tag == revocationReasonTag else {
                throw .invalidStructure
            }
            var reasonBody = DERCursor(reason.contentBytes)
            _ = try decodeEnumerated(readElement(
                &reasonBody,
                budget: &budget
            ))
            try requireFullyConsumed(reasonBody)
        }
        try requireFullyConsumed(body)
        return .revoked(revocationTime)
    }

    private static func parseExtensions(
        _ explicit: DERElementView,
        expectedTag: DERTag,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> ParsedExtensions {
        guard explicit.tag == expectedTag else { throw .invalidStructure }
        var explicitBody = DERCursor(explicit.contentBytes)
        let sequence = try readElement(&explicitBody, budget: &budget)
        try requireFullyConsumed(explicitBody)
        guard sequence.tag == sequenceTag,
              !sequence.contentBytes.isEmpty else {
            throw .invalidStructure
        }
        var body = DERCursor(sequence.contentBytes)
        var seen = ContiguousArray<ContiguousArray<UInt64>>()
        var nonce: OwnedBytes?
        var signedCertificateTimestamps: SignedCertificateTimestampList?
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
            if oid == nonceOID {
                guard nonce == nil else { throw .invalidStructure }
                var nonceBody = DERCursor(value.contentBytes)
                let nonceElement = try readElement(
                    &nonceBody,
                    budget: &budget
                )
                try requireFullyConsumed(nonceBody)
                guard nonceElement.tag == octetStringTag else {
                    throw .invalidStructure
                }
                nonce = OwnedBytes(copying: nonceElement.contentBytes)
            } else if oid == signedCertificateTimestampOID {
                guard !critical, signedCertificateTimestamps == nil else {
                    throw .invalidStructure
                }
                var timestampBody = DERCursor(value.contentBytes)
                let timestampOctets = try readElement(
                    &timestampBody,
                    budget: &budget
                )
                try requireFullyConsumed(timestampBody)
                guard timestampOctets.tag == octetStringTag else {
                    throw .invalidStructure
                }
                do {
                    signedCertificateTimestamps =
                        try SignedCertificateTimestampList(
                            encoded: timestampOctets.contentBytes
                        )
                } catch let error {
                    throw .certificateTransparency(error)
                }
            } else if critical {
                throw .unsupportedCriticalExtension(oid)
            }
        }
        return ParsedExtensions(
            nonce: nonce,
            signedCertificateTimestamps: signedCertificateTimestamps
        )
    }

    private static func requireOCSPSigningPurpose(
        _ certificate: borrowing X509Certificate
    ) throws(OCSPResponseError) {
        for extensionValue in certificate.extensions
        where extensionValue.isCritical {
            guard processedResponderCriticalExtensions.contains(
                extensionValue.objectIdentifier
            ) else {
                throw .unsupportedCriticalExtension(
                    extensionValue.objectIdentifier
                )
            }
        }
        if let keyUsage = certificate.extensions.first(where: {
            $0.objectIdentifier == keyUsageOID
        }) {
            let bits = try decodeBitString(keyUsage.value)
            guard !bits.bytes.isEmpty,
                  bits.bytes.span[0] & 0x80 != 0 else {
                throw .responderCertificateKeyUsageViolation
            }
        }
        guard let extendedKeyUsage = certificate.extensions.first(where: {
            $0.objectIdentifier == extendedKeyUsageOID
        }) else {
            throw .responderCertificateExtendedKeyUsageViolation
        }
        let purposes = try decodeOIDSequence(extendedKeyUsage.value)
        guard purposes.contains(ocspSigningOID) else {
            throw .responderCertificateExtendedKeyUsageViolation
        }
    }

    private static func decodeBitString(
        _ value: borrowing OwnedBytes
    ) throws(OCSPResponseError) -> DERBitString {
        var budget = try makeBudget(value.count)
        var cursor = DERCursor(value.span)
        let element = try readElement(&cursor, budget: &budget)
        try requireFullyConsumed(cursor)
        do {
            return try DERPrimitiveCodec.decodeBitString(from: element)
        } catch {
            throw .responderCertificateKeyUsageViolation
        }
    }

    private static func decodeOIDSequence(
        _ value: borrowing OwnedBytes
    ) throws(OCSPResponseError) -> ContiguousArray<ContiguousArray<UInt64>> {
        var budget = try makeBudget(value.count)
        var cursor = DERCursor(value.span)
        let sequence = try readElement(&cursor, budget: &budget)
        try requireFullyConsumed(cursor)
        guard sequence.tag == sequenceTag,
              !sequence.contentBytes.isEmpty else {
            throw .responderCertificateExtendedKeyUsageViolation
        }
        var body = DERCursor(sequence.contentBytes)
        var result = ContiguousArray<ContiguousArray<UInt64>>()
        while !body.isAtEnd {
            let element = try readElement(&body, budget: &budget)
            let oid: ContiguousArray<UInt64>
            do {
                oid = try DERPrimitiveCodec.decodeObjectIdentifier(
                    from: element
                )
            } catch {
                throw .responderCertificateExtendedKeyUsageViolation
            }
            guard !result.contains(oid) else {
                throw .responderCertificateExtendedKeyUsageViolation
            }
            result.append(oid)
        }
        return result
    }

    private static func validateFreshness(
        _ response: borrowing SingleResponse,
        at instant: VerificationInstant,
        policy: OCSPValidationPolicy
    ) throws(OCSPResponseError) {
        let futureLimit = addingSeconds(
            policy.maximumClockSkewSeconds,
            to: instant
        )
        guard response.thisUpdate <= futureLimit else {
            throw .producedInFuture
        }
        if let nextUpdate = response.nextUpdate {
            let expiration = addingSeconds(
                policy.maximumClockSkewSeconds,
                to: nextUpdate
            )
            guard instant <= expiration else { throw .expired }
            return
        }
        guard !policy.requireNextUpdate else { throw .missingNextUpdate }
        let maximumAge = addingSeconds(
            policy.maximumAgeWithoutNextUpdateSeconds,
            to: response.thisUpdate
        )
        let expiration = addingSeconds(
            policy.maximumClockSkewSeconds,
            to: maximumAge
        )
        guard instant <= expiration else { throw .expired }
    }

    private static func requireCanonicalSerial(
        _ element: DERElementView
    ) throws(OCSPResponseError) {
        guard element.tag == integerTag else { throw .invalidSerialNumber }
        let bytes = element.contentBytes
        guard !bytes.isEmpty,
              bytes[0] & 0x80 == 0,
              !(bytes.count > 1
                && bytes[0] == 0
                && bytes[1] & 0x80 == 0) else {
            throw .invalidSerialNumber
        }
    }

    private static func decodeGeneralizedTime(
        _ element: DERElementView
    ) throws(OCSPResponseError) -> VerificationInstant {
        guard element.tag == generalizedTimeTag,
              element.contentBytes.count == 15,
              let decoded = X509Validity.decodeTime(element.contentBytes) else {
            throw .invalidTime
        }
        return decoded.instant
    }

    private static func decodeEnumerated(
        _ element: DERElementView
    ) throws(OCSPResponseError) -> UInt64 {
        guard element.tag == enumeratedTag else { throw .invalidStructure }
        let bytes = element.contentBytes
        guard !bytes.isEmpty,
              bytes[0] & 0x80 == 0,
              !(bytes.count > 1
                && bytes[0] == 0
                && bytes[1] & 0x80 == 0),
              bytes.count <= 8 else {
            throw .invalidStructure
        }
        var result: UInt64 = 0
        var index = 0
        while index < bytes.count {
            result = (result << 8) | UInt64(bytes[index])
            index += 1
        }
        return result
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

    private static func makeBudget(
        _ byteCount: Int
    ) throws(OCSPResponseError) -> ParsingBudget {
        do {
            return try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: byteCount
            )
        } catch let error {
            throw .resourceLimit(error)
        }
    }

    @_lifetime(copy cursor)
    private static func readElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget
    ) throws(OCSPResponseError) -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch let error {
            throw .der(error)
        }
    }

    private static func requireFullyConsumed(
        _ cursor: DERCursor
    ) throws(OCSPResponseError) {
        do {
            try cursor.requireFullyConsumed()
        } catch let error {
            throw .der(error)
        }
    }

    private enum IdentifierHashAlgorithm: Sendable, Hashable {
        case sha1
        case sha256

        var digestByteCount: Int {
            switch self {
            case .sha1: return OCSPIdentifierHash.digestByteCount
            case .sha256: return SHA256.digestByteCount
            }
        }

        func hash(_ bytes: Span<UInt8>) throws(OCSPResponseError)
            -> ContiguousArray<UInt8>
        {
            switch self {
            case .sha1:
                return OCSPIdentifierHash.hash(bytes)
            case .sha256:
                var output = ContiguousArray<UInt8>(
                    repeating: 0,
                    count: SHA256.digestByteCount
                )
                do {
                    var destination = output.mutableSpan
                    try SHA256.hash(bytes, into: &destination)
                } catch {
                    throw .invalidIdentifierHashLength
                }
                return output
            }
        }
    }

    private struct CertificateIdentifier: Sendable, Hashable {
        let hashAlgorithm: IdentifierHashAlgorithm
        let issuerNameHash: OwnedBytes
        let issuerKeyHash: OwnedBytes
        let serialNumber: OwnedBytes

        borrowing func matches(
            certificate: borrowing X509Certificate,
            issuer: borrowing X509Certificate
        ) throws(OCSPResponseError) -> Bool {
            guard ConstantTime.equal(
                serialNumber.span,
                certificate.serialNumber.span
            ) else {
                return false
            }
            let expectedNameHash = try hashAlgorithm.hash(
                issuer.subjectName.span
            )
            let expectedKeyHash = try issuer.subjectPublicKeyInfo
                .withPublicKeyBytes { key throws(OCSPResponseError) in
                    try hashAlgorithm.hash(key)
                }
            return ConstantTime.equal(
                issuerNameHash.span,
                expectedNameHash.span
            ) && ConstantTime.equal(
                issuerKeyHash.span,
                expectedKeyHash.span
            )
        }
    }

    private enum CertificateStatus: Sendable, Hashable {
        case good
        case revoked(VerificationInstant)
        case unknown
    }

    private struct SingleResponse: Sendable, Hashable {
        let certificateIdentifier: CertificateIdentifier
        let status: CertificateStatus
        let thisUpdate: VerificationInstant
        let nextUpdate: VerificationInstant?
        let signedCertificateTimestamps: SignedCertificateTimestampList?

        borrowing func matches(
            certificate: borrowing X509Certificate,
            issuer: borrowing X509Certificate
        ) throws(OCSPResponseError) -> Bool {
            try certificateIdentifier.matches(
                certificate: certificate,
                issuer: issuer
            )
        }
    }

    private enum ResponderIdentifier: Sendable, Hashable {
        case name(OwnedBytes)
        case keyHash(OwnedBytes)

        borrowing func matches(
            _ certificate: borrowing X509Certificate
        ) -> Bool {
            switch self {
            case .name(let name):
                return name == certificate.subjectName
            case .keyHash(let expected):
                return certificate.subjectPublicKeyInfo.withPublicKeyBytes {
                    publicKey in
                    let actual = OCSPIdentifierHash.hash(publicKey)
                    return ConstantTime.equal(expected.span, actual.span)
                }
            }
        }
    }

    private struct ParsedResponseData {
        let responderIdentifier: ResponderIdentifier
        let producedAt: VerificationInstant
        let responses: ContiguousArray<SingleResponse>
        let nonce: OwnedBytes?
        let signedCertificateTimestamps: SignedCertificateTimestampList?
    }

    private struct ParsedExtensions {
        let nonce: OwnedBytes?
        let signedCertificateTimestamps: SignedCertificateTimestampList?

        init(
            nonce: consuming OwnedBytes? = nil,
            signedCertificateTimestamps: SignedCertificateTimestampList? = nil
        ) {
            self.nonce = nonce
            self.signedCertificateTimestamps = signedCertificateTimestamps
        }
    }

    private static let basicResponseOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 5, 5, 7, 48, 1, 1,
    ]
    private static let sha1OID: ContiguousArray<UInt64> = [
        1, 3, 14, 3, 2, 26,
    ]
    private static let sha256OID: ContiguousArray<UInt64> = [
        2, 16, 840, 1, 101, 3, 4, 2, 1,
    ]
    private static let nonceOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 5, 5, 7, 48, 1, 2,
    ]
    private static let signedCertificateTimestampOID:
        ContiguousArray<UInt64> = [
            1, 3, 6, 1, 4, 1, 11_129, 2, 4, 5,
        ]
    private static let ocspSigningOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 5, 5, 7, 3, 9,
    ]
    private static let keyUsageOID: ContiguousArray<UInt64> = [2, 5, 29, 15]
    private static let extendedKeyUsageOID: ContiguousArray<UInt64> = [
        2, 5, 29, 37,
    ]
    private static let processedResponderCriticalExtensions:
        ContiguousArray<ContiguousArray<UInt64>> = [
            keyUsageOID,
            extendedKeyUsageOID,
            [2, 5, 29, 19],
            [1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
        ]

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
    private static let enumeratedTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 10
    )
    private static let generalizedTimeTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 24
    )
    private static let responseBytesTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 0
    )
    private static let versionTag = responseBytesTag
    private static let certificatesTag = responseBytesTag
    private static let responderByNameTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 1
    )
    private static let responderByKeyTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: false,
        number: 2
    )
    private static let responseExtensionsTag = responderByNameTag
    private static let singleExtensionsTag = responderByNameTag
    private static let nextUpdateTag = responseBytesTag
    private static let goodStatusTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: false,
        number: 0
    )
    private static let revokedStatusTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: true,
        number: 1
    )
    private static let unknownStatusTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: false,
        number: 2
    )
    private static let revocationReasonTag = responseBytesTag
}
