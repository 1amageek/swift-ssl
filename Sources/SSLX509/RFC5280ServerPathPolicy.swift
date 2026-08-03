import SSLCore
import SSLASN1

/// RFC 5280 extension policy for modern TLS server identities.
///
/// The policy rejects unknown critical extensions, requires compatible leaf
/// key usage and extended key usage when present, applies DNS name constraints,
/// and can require a direct certificate-policy OID across the non-anchor path.
/// Policy mapping and non-DNS name constraints are rejected instead of being
/// silently ignored.
public struct RFC5280ServerPathPolicy: X509PathPolicyEvaluating, Sendable {
    private enum LeafAuthenticationPurpose: Sendable {
        case server
        case client
    }

    public let requiredCertificatePolicyObjectIdentifiers:
        ContiguousArray<ContiguousArray<UInt64>>
    private let leafAuthenticationPurpose: LeafAuthenticationPurpose

    public init(
        requiredCertificatePolicyObjectIdentifiers:
            ContiguousArray<ContiguousArray<UInt64>> = []
    ) {
        self.requiredCertificatePolicyObjectIdentifiers =
            requiredCertificatePolicyObjectIdentifiers
        self.leafAuthenticationPurpose = .server
    }

    package init(
        clientAuthenticationRequiredCertificatePolicyObjectIdentifiers:
            ContiguousArray<ContiguousArray<UInt64>>
    ) {
        self.requiredCertificatePolicyObjectIdentifiers =
            clientAuthenticationRequiredCertificatePolicyObjectIdentifiers
        self.leafAuthenticationPurpose = .client
    }

    public func evaluate(
        path: borrowing ContiguousArray<X509Certificate>,
        hostname: Span<UInt8>?
    ) throws(X509PathError) {
        guard !path.isEmpty else {
            throw .invalidPathLength
        }
        try validateCriticalExtensions(path)
        try validateLeafPurpose(path[0])
        try validateNameConstraints(path)
        try validateCertificatePolicies(path)
        if let hostname {
            do {
                try path[0].verifyDNSName(hostname)
            } catch let error as X509IdentityError {
                throw .identity(error)
            } catch {
                throw .identity(.malformedSubjectAlternativeName)
            }
        }
    }

    private func validateCriticalExtensions(
        _ path: borrowing ContiguousArray<X509Certificate>
    ) throws(X509PathError) {
        var certificateIndex = 0
        while certificateIndex < path.count {
            let extensions = path[certificateIndex].extensions
            for extensionValue in extensions where extensionValue.isCritical {
                guard Self.processedCriticalExtensionObjectIdentifiers
                    .contains(extensionValue.objectIdentifier) else {
                    throw .unsupportedCriticalExtension(
                        extensionValue.objectIdentifier
                    )
                }
            }
            certificateIndex += 1
        }
    }

    private func validateLeafPurpose(
        _ leaf: borrowing X509Certificate
    ) throws(X509PathError) {
        if let keyUsage = leaf.extensions.first(where: {
            $0.objectIdentifier == Self.keyUsageOID
        }) {
            let bits = try Self.decodeBitString(
                keyUsage.value,
                failure: .invalidKeyUsage
            )
            guard !bits.bytes.isEmpty,
                  bits.bytes.span[0] & 0x80 != 0 else {
                throw .leafKeyUsageViolation
            }
        }

        guard let extendedKeyUsage = leaf.extensions.first(where: {
                  $0.objectIdentifier == Self.extendedKeyUsageOID
              }) else {
            return
        }
        let purposes = try Self.decodeOIDSequence(
            extendedKeyUsage.value,
            failure: .invalidExtendedKeyUsage
        )
        let requiredPurpose: ContiguousArray<UInt64>
        switch leafAuthenticationPurpose {
        case .server:
            requiredPurpose = Self.serverAuthenticationOID
        case .client:
            requiredPurpose = Self.clientAuthenticationOID
        }
        guard purposes.contains(requiredPurpose)
                || purposes.contains(Self.anyExtendedKeyUsageOID) else {
            throw .extendedKeyUsageViolation
        }
    }

    private func validateNameConstraints(
        _ path: borrowing ContiguousArray<X509Certificate>
    ) throws(X509PathError) {
        guard path.count > 1 else { return }
        var issuerIndex = 1
        while issuerIndex < path.count {
            for extensionValue in path[issuerIndex].extensions
            where extensionValue.objectIdentifier == Self.nameConstraintsOID {
                let constraints = try Self.decodeNameConstraints(
                    extensionValue.value
                )
                var subordinateIndex = 0
                while subordinateIndex < issuerIndex {
                    let dnsNames = try Self.decodeDNSNames(
                        path[subordinateIndex]
                    )
                    for name in dnsNames {
                        for excluded in constraints.excluded
                        where Self.isWithinDNSSubtree(
                            name.span,
                            constraint: excluded.span
                        ) {
                            throw .excludedNameConstraint
                        }
                        if !constraints.permitted.isEmpty {
                            var permitted = false
                            for candidate in constraints.permitted
                            where Self.isWithinDNSSubtree(
                                name.span,
                                constraint: candidate.span
                            ) {
                                permitted = true
                                break
                            }
                            guard permitted else {
                                throw .permittedNameConstraintViolation
                            }
                        }
                    }
                    subordinateIndex += 1
                }
            }
            issuerIndex += 1
        }
    }

    private func validateCertificatePolicies(
        _ path: borrowing ContiguousArray<X509Certificate>
    ) throws(X509PathError) {
        guard !requiredCertificatePolicyObjectIdentifiers.isEmpty else {
            return
        }
        guard path.count > 1 else {
            throw .certificatePolicyViolation
        }

        var accepted = requiredCertificatePolicyObjectIdentifiers
        var index = 0
        while index < path.count - 1 {
            guard let extensionValue = path[index].extensions.first(where: {
                $0.objectIdentifier == Self.certificatePoliciesOID
            }) else {
                throw .certificatePolicyViolation
            }
            let policies = try Self.decodeCertificatePolicies(
                extensionValue.value
            )
            if policies.contains(Self.anyPolicyOID) {
                index += 1
                continue
            }
            accepted.removeAll { !policies.contains($0) }
            guard !accepted.isEmpty else {
                throw .certificatePolicyViolation
            }
            index += 1
        }
    }

    private static func decodeNameConstraints(
        _ value: borrowing OwnedBytes
    ) throws(X509PathError) -> DNSConstraints {
        var budget = try makeBudget(value.count, failure: .invalidNameConstraints)
        var cursor = DERCursor(value.span)
        let root = try readElement(
            &cursor,
            budget: &budget,
            failure: .invalidNameConstraints
        )
        try requireFullyConsumed(cursor, failure: .invalidNameConstraints)
        guard root.tag == sequenceTag else {
            throw .invalidNameConstraints
        }

        var body = DERCursor(root.contentBytes)
        var permitted = ContiguousArray<OwnedBytes>()
        var excluded = ContiguousArray<OwnedBytes>()
        var sawPermitted = false
        var sawExcluded = false
        while !body.isAtEnd {
            let group = try readElement(
                &body,
                budget: &budget,
                failure: .invalidNameConstraints
            )
            guard group.tag.tagClass == .contextSpecific,
                  group.tag.isConstructed,
                  group.tag.number == 0 || group.tag.number == 1 else {
                throw .invalidNameConstraints
            }
            if group.tag.number == 0 {
                guard !sawPermitted else { throw .invalidNameConstraints }
                sawPermitted = true
            } else {
                guard !sawExcluded else { throw .invalidNameConstraints }
                sawExcluded = true
            }
            var subtrees = DERCursor(group.contentBytes)
            guard !subtrees.isAtEnd else { throw .invalidNameConstraints }
            while !subtrees.isAtEnd {
                let subtree = try readElement(
                    &subtrees,
                    budget: &budget,
                    failure: .invalidNameConstraints
                )
                guard subtree.tag == sequenceTag else {
                    throw .invalidNameConstraints
                }
                var subtreeBody = DERCursor(subtree.contentBytes)
                let base = try readElement(
                    &subtreeBody,
                    budget: &budget,
                    failure: .invalidNameConstraints
                )
                guard subtreeBody.isAtEnd else {
                    throw .unsupportedNameConstraintBounds
                }
                guard base.tag == dnsNameTag else {
                    throw .unsupportedNameConstraintType(base.tag.number)
                }
                let canonical = try canonicalDNSConstraint(base.contentBytes)
                if group.tag.number == 0 {
                    permitted.append(OwnedBytes(consuming: canonical))
                } else {
                    excluded.append(OwnedBytes(consuming: canonical))
                }
            }
        }
        guard sawPermitted || sawExcluded else {
            throw .invalidNameConstraints
        }
        return DNSConstraints(permitted: permitted, excluded: excluded)
    }

    private static func decodeDNSNames(
        _ certificate: borrowing X509Certificate
    ) throws(X509PathError) -> ContiguousArray<OwnedBytes> {
        guard let subjectAlternativeName = certificate.extensions.first(where: {
            $0.objectIdentifier == subjectAlternativeNameOID
        }) else {
            return []
        }
        var budget = try makeBudget(
            subjectAlternativeName.value.count,
            failure: .invalidSubjectAlternativeName
        )
        var cursor = DERCursor(subjectAlternativeName.value.span)
        let root = try readElement(
            &cursor,
            budget: &budget,
            failure: .invalidSubjectAlternativeName
        )
        try requireFullyConsumed(
            cursor,
            failure: .invalidSubjectAlternativeName
        )
        guard root.tag == sequenceTag else {
            throw .invalidSubjectAlternativeName
        }

        var body = DERCursor(root.contentBytes)
        var names = ContiguousArray<OwnedBytes>()
        while !body.isAtEnd {
            let name = try readElement(
                &body,
                budget: &budget,
                failure: .invalidSubjectAlternativeName
            )
            guard name.tag.tagClass == .contextSpecific,
                  name.tag.number <= 8 else {
                throw .invalidSubjectAlternativeName
            }
            guard name.tag == dnsNameTag else { continue }
            do {
                names.append(
                    OwnedBytes(
                        consuming: try X509DNSName.canonicalCertificateName(
                            name.contentBytes
                        )
                    )
                )
            } catch {
                throw .invalidSubjectAlternativeName
            }
        }
        return names
    }

    private static func decodeCertificatePolicies(
        _ value: borrowing OwnedBytes
    ) throws(X509PathError) -> ContiguousArray<ContiguousArray<UInt64>> {
        var budget = try makeBudget(
            value.count,
            failure: .invalidCertificatePolicies
        )
        var cursor = DERCursor(value.span)
        let root = try readElement(
            &cursor,
            budget: &budget,
            failure: .invalidCertificatePolicies
        )
        try requireFullyConsumed(cursor, failure: .invalidCertificatePolicies)
        guard root.tag == sequenceTag, !root.contentBytes.isEmpty else {
            throw .invalidCertificatePolicies
        }

        var body = DERCursor(root.contentBytes)
        var policies = ContiguousArray<ContiguousArray<UInt64>>()
        while !body.isAtEnd {
            let policyInformation = try readElement(
                &body,
                budget: &budget,
                failure: .invalidCertificatePolicies
            )
            guard policyInformation.tag == sequenceTag else {
                throw .invalidCertificatePolicies
            }
            var policyBody = DERCursor(policyInformation.contentBytes)
            let identifier = try readElement(
                &policyBody,
                budget: &budget,
                failure: .invalidCertificatePolicies
            )
            let oid = try decodeOID(
                identifier,
                failure: .invalidCertificatePolicies
            )
            if !policyBody.isAtEnd {
                let qualifiers = try readElement(
                    &policyBody,
                    budget: &budget,
                    failure: .invalidCertificatePolicies
                )
                guard qualifiers.tag == sequenceTag else {
                    throw .invalidCertificatePolicies
                }
                try requireFullyConsumed(
                    policyBody,
                    failure: .invalidCertificatePolicies
                )
            }
            guard !policies.contains(oid) else {
                throw .invalidCertificatePolicies
            }
            policies.append(oid)
        }
        return policies
    }

    private static func decodeOIDSequence(
        _ value: borrowing OwnedBytes,
        failure: X509PathError
    ) throws(X509PathError) -> ContiguousArray<ContiguousArray<UInt64>> {
        var budget = try makeBudget(value.count, failure: failure)
        var cursor = DERCursor(value.span)
        let root = try readElement(&cursor, budget: &budget, failure: failure)
        try requireFullyConsumed(cursor, failure: failure)
        guard root.tag == sequenceTag, !root.contentBytes.isEmpty else {
            throw failure
        }
        var body = DERCursor(root.contentBytes)
        var result = ContiguousArray<ContiguousArray<UInt64>>()
        while !body.isAtEnd {
            let element = try readElement(
                &body,
                budget: &budget,
                failure: failure
            )
            let oid = try decodeOID(element, failure: failure)
            guard !result.contains(oid) else { throw failure }
            result.append(oid)
        }
        return result
    }

    private static func decodeBitString(
        _ value: borrowing OwnedBytes,
        failure: X509PathError
    ) throws(X509PathError) -> DERBitString {
        var budget = try makeBudget(value.count, failure: failure)
        var cursor = DERCursor(value.span)
        let element = try readElement(
            &cursor,
            budget: &budget,
            failure: failure
        )
        try requireFullyConsumed(cursor, failure: failure)
        do {
            return try DERPrimitiveCodec.decodeBitString(from: element)
        } catch {
            throw failure
        }
    }

    private static func canonicalDNSConstraint(
        _ bytes: Span<UInt8>
    ) throws(X509PathError) -> ContiguousArray<UInt8> {
        guard !bytes.isEmpty else { throw .invalidNameConstraints }
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            guard byte < 0x80, byte != 0 else {
                throw .invalidNameConstraints
            }
            if byte >= 0x41, byte <= 0x5A {
                result.append(byte + 0x20)
            } else {
                result.append(byte)
            }
            index += 1
        }
        if result.last == 0x2E { result.removeLast() }
        let domainStart = result.first == 0x2E ? 1 : 0
        guard domainStart < result.count else {
            throw .invalidNameConstraints
        }
        var labelStart = domainStart
        index = domainStart
        while index <= result.count {
            if index == result.count || result[index] == 0x2E {
                let labelCount = index - labelStart
                guard labelCount > 0, labelCount <= 63 else {
                    throw .invalidNameConstraints
                }
                var labelIndex = labelStart
                while labelIndex < index {
                    let byte = result[labelIndex]
                    let isAlphaNumeric = (byte >= 0x61 && byte <= 0x7A)
                        || (byte >= 0x30 && byte <= 0x39)
                    guard isAlphaNumeric || byte == 0x2D else {
                        throw .invalidNameConstraints
                    }
                    labelIndex += 1
                }
                guard result[labelStart] != 0x2D,
                      result[index - 1] != 0x2D else {
                    throw .invalidNameConstraints
                }
                labelStart = index + 1
            }
            index += 1
        }
        return result
    }

    private static func isWithinDNSSubtree(
        _ name: Span<UInt8>,
        constraint: Span<UInt8>
    ) -> Bool {
        let leadingDot = constraint[0] == 0x2E
        let suffix = leadingDot
            ? constraint.extracting(1..<constraint.count)
            : constraint
        let nameStart = name.count >= 2 && name[0] == 0x2A && name[1] == 0x2E
            ? 2
            : 0
        let nameCount = name.count - nameStart
        guard nameCount >= suffix.count else { return false }
        let suffixStart = name.count - suffix.count
        var index = 0
        while index < suffix.count {
            guard name[suffixStart + index] == suffix[index] else {
                return false
            }
            index += 1
        }
        if nameCount == suffix.count {
            return !leadingDot
        }
        return suffixStart > nameStart && name[suffixStart - 1] == 0x2E
    }

    private static func makeBudget(
        _ byteCount: Int,
        failure: X509PathError
    ) throws(X509PathError) -> ParsingBudget {
        do {
            return try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: byteCount
            )
        } catch {
            throw failure
        }
    }

    @_lifetime(copy cursor)
    private static func readElement(
        _ cursor: inout DERCursor,
        budget: inout ParsingBudget,
        failure: X509PathError
    ) throws(X509PathError) -> DERElementView {
        do {
            return try cursor.readElement(using: &budget)
        } catch {
            throw failure
        }
    }

    private static func requireFullyConsumed(
        _ cursor: DERCursor,
        failure: X509PathError
    ) throws(X509PathError) {
        do {
            try cursor.requireFullyConsumed()
        } catch {
            throw failure
        }
    }

    private static func decodeOID(
        _ element: DERElementView,
        failure: X509PathError
    ) throws(X509PathError) -> ContiguousArray<UInt64> {
        do {
            return try DERPrimitiveCodec.decodeObjectIdentifier(from: element)
        } catch {
            throw failure
        }
    }

    private struct DNSConstraints {
        let permitted: ContiguousArray<OwnedBytes>
        let excluded: ContiguousArray<OwnedBytes>
    }

    private static let processedCriticalExtensionObjectIdentifiers:
        ContiguousArray<ContiguousArray<UInt64>> = [
            keyUsageOID,
            subjectAlternativeNameOID,
            basicConstraintsOID,
            nameConstraintsOID,
            certificatePoliciesOID,
            extendedKeyUsageOID,
        ]
    private static let keyUsageOID: ContiguousArray<UInt64> = [2, 5, 29, 15]
    private static let subjectAlternativeNameOID: ContiguousArray<UInt64> = [
        2, 5, 29, 17,
    ]
    private static let basicConstraintsOID: ContiguousArray<UInt64> = [
        2, 5, 29, 19,
    ]
    private static let nameConstraintsOID: ContiguousArray<UInt64> = [
        2, 5, 29, 30,
    ]
    private static let certificatePoliciesOID: ContiguousArray<UInt64> = [
        2, 5, 29, 32,
    ]
    private static let extendedKeyUsageOID: ContiguousArray<UInt64> = [
        2, 5, 29, 37,
    ]
    private static let serverAuthenticationOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 5, 5, 7, 3, 1,
    ]
    private static let clientAuthenticationOID: ContiguousArray<UInt64> = [
        1, 3, 6, 1, 5, 5, 7, 3, 2,
    ]
    private static let anyExtendedKeyUsageOID: ContiguousArray<UInt64> = [
        2, 5, 29, 37, 0,
    ]
    private static let anyPolicyOID: ContiguousArray<UInt64> = [
        2, 5, 29, 32, 0,
    ]
    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let dnsNameTag = DERTag(
        tagClass: .contextSpecific,
        isConstructed: false,
        number: 2
    )
}
