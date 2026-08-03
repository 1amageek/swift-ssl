import XCTest
import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLX509

final class X509PathPolicyTests: XCTestCase {
    func testRejectsUnknownCriticalExtension() throws {
        let unknown = try makeExtension(
            objectIdentifier: [1, 2, 3, 4],
            critical: true,
            value: try makeElement(
                tag: SwiftSSLASN1.DERTag(
                    tagClass: .universal,
                    isConstructed: false,
                    number: 5
                ),
                content: []
            )
        )
        let certificate = try makeCertificate(extensions: [unknown])

        do {
            try RFC5280ServerPathPolicy().evaluate(
                path: [certificate],
                hostname: nil
            )
            XCTFail("unknown critical extension was accepted")
        } catch {
            XCTAssertEqual(error, .unsupportedCriticalExtension([1, 2, 3, 4]))
        }
    }

    func testRejectsLeafWithoutDigitalSignatureKeyUsage() throws {
        let keyUsage = try makeExtension(
            objectIdentifier: [2, 5, 29, 15],
            critical: true,
            value: try makeElement(
                tag: SwiftSSLASN1.DERTag(
                    tagClass: .universal,
                    isConstructed: false,
                    number: 3
                ),
                content: [5, 0x20]
            )
        )
        let certificate = try makeCertificate(extensions: [keyUsage])

        do {
            try RFC5280ServerPathPolicy().evaluate(
                path: [certificate],
                hostname: nil
            )
            XCTFail("non-signing leaf key usage was accepted")
        } catch {
            XCTAssertEqual(error, .leafKeyUsageViolation)
        }
    }

    func testRejectsClientAuthenticationOnlyLeafForServerIdentity() throws {
        let serverName = ContiguousArray("api.example".utf8)
        let subjectAlternativeName = try makeDNSSubjectAlternativeName(
            serverName
        )
        let clientAuthentication = try makeOID(
            [1, 3, 6, 1, 5, 5, 7, 3, 2]
        )
        let extendedKeyUsage = try makeExtension(
            objectIdentifier: [2, 5, 29, 37],
            critical: false,
            value: try makeSequence([clientAuthentication])
        )
        let certificate = try makeCertificate(
            extensions: [subjectAlternativeName, extendedKeyUsage]
        )

        do {
            try RFC5280ServerPathPolicy().evaluate(
                path: [certificate],
                hostname: serverName.span
            )
            XCTFail("client-authentication-only leaf was accepted")
        } catch {
            XCTAssertEqual(error, .extendedKeyUsageViolation)
        }
    }

    func testAppliesPermittedDNSNameConstraint() throws {
        let permittedConstraint = try makeDNSNameConstraints(
            permitted: ContiguousArray("example.com".utf8)
        )
        let anchor = try makeCertificate(extensions: [permittedConstraint])
        let allowedName = ContiguousArray("service.example.com".utf8)
        let allowedLeaf = try makeCertificate(
            extensions: [try makeDNSSubjectAlternativeName(allowedName)]
        )
        let blockedName = ContiguousArray("service.invalid".utf8)
        let blockedLeaf = try makeCertificate(
            extensions: [try makeDNSSubjectAlternativeName(blockedName)]
        )
        let policy = RFC5280ServerPathPolicy()

        XCTAssertNoThrow(try policy.evaluate(
            path: [allowedLeaf, anchor],
            hostname: allowedName.span
        ))
        do {
            try policy.evaluate(
                path: [blockedLeaf, anchor],
                hostname: blockedName.span
            )
            XCTFail("DNS name outside the permitted subtree was accepted")
        } catch {
            XCTAssertEqual(error, .permittedNameConstraintViolation)
        }
    }

    func testRequiresConfiguredCertificatePolicy() throws {
        let requiredOID: ContiguousArray<UInt64> = [1, 3, 6, 1, 4, 1, 55555, 1]
        let otherOID: ContiguousArray<UInt64> = [1, 3, 6, 1, 4, 1, 55555, 2]
        let anchor = try makeCertificate(extensions: [])
        let matchingLeaf = try makeCertificate(
            extensions: [try makeCertificatePolicies([requiredOID])]
        )
        let mismatchingLeaf = try makeCertificate(
            extensions: [try makeCertificatePolicies([otherOID])]
        )
        let policy = RFC5280ServerPathPolicy(
            requiredCertificatePolicyObjectIdentifiers: [requiredOID]
        )

        XCTAssertNoThrow(try policy.evaluate(
            path: [matchingLeaf, anchor],
            hostname: nil
        ))
        do {
            try policy.evaluate(
                path: [mismatchingLeaf, anchor],
                hostname: nil
            )
            XCTFail("certificate path without the required policy was accepted")
        } catch {
            XCTAssertEqual(error, .certificatePolicyViolation)
        }
    }
}

private func makeCertificate(
    extensions: [OwnedBytes]
) throws -> X509Certificate {
    let algorithm = try makeSequence([
        try makeOID([1, 3, 101, 112]),
    ])
    let version = try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: true,
            number: 0
        ),
        content: try makePositiveInteger(2)
    )
    let emptyName = try makeSequence([])
    let validity = try makeSequence([
        try makeElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 23
            ),
            content: OwnedBytes(
                consuming: ContiguousArray("250101000000Z".utf8)
            )
        ),
        try makeElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 23
            ),
            content: OwnedBytes(
                consuming: ContiguousArray("350101000000Z".utf8)
            )
        ),
    ])
    let publicKeyBits = OwnedBytes(
        consuming: ContiguousArray([0] + Array(repeating: UInt8(7), count: 32))
    )
    let subjectPublicKeyInfo = try makeSequence([
        algorithm,
        try makeElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 3
            ),
            content: publicKeyBits
        ),
    ])

    var tbsFields = [
        version,
        try makePositiveInteger(1),
        algorithm,
        emptyName,
        validity,
        emptyName,
        subjectPublicKeyInfo,
    ]
    if !extensions.isEmpty {
        tbsFields.append(try makeElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 3
            ),
            content: try makeSequence(extensions)
        ))
    }
    let tbsCertificate = try makeSequence(tbsFields)
    let signature = try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 3
        ),
        content: OwnedBytes(consuming: [0, 1])
    )
    let encoded = try makeSequence([tbsCertificate, algorithm, signature])
    return try X509Certificate(der: encoded.span)
}

private func makeDNSSubjectAlternativeName(
    _ name: ContiguousArray<UInt8>
) throws -> OwnedBytes {
    let generalName = try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: false,
            number: 2
        ),
        content: OwnedBytes(consuming: name)
    )
    return try makeExtension(
        objectIdentifier: [2, 5, 29, 17],
        critical: false,
        value: try makeSequence([generalName])
    )
}

private func makeDNSNameConstraints(
    permitted: ContiguousArray<UInt8>
) throws -> OwnedBytes {
    let base = try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: false,
            number: 2
        ),
        content: OwnedBytes(consuming: permitted)
    )
    let subtree = try makeSequence([base])
    let permittedSubtrees = try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: true,
            number: 0
        ),
        content: subtree
    )
    return try makeExtension(
        objectIdentifier: [2, 5, 29, 30],
        critical: true,
        value: try makeSequence([permittedSubtrees])
    )
}

private func makeCertificatePolicies(
    _ identifiers: [ContiguousArray<UInt64>]
) throws -> OwnedBytes {
    var policyInformation = [OwnedBytes]()
    for identifier in identifiers {
        policyInformation.append(try makeSequence([try makeOID(identifier)]))
    }
    return try makeExtension(
        objectIdentifier: [2, 5, 29, 32],
        critical: false,
        value: try makeSequence(policyInformation)
    )
}

private func makeExtension(
    objectIdentifier: ContiguousArray<UInt64>,
    critical: Bool,
    value: OwnedBytes
) throws -> OwnedBytes {
    var fields = [try makeOID(objectIdentifier)]
    if critical {
        var booleanWriter = try DERWriter(maximumByteCount: 3)
        try booleanWriter.appendBoolean(true)
        fields.append(booleanWriter.finish())
    }
    fields.append(try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 4
        ),
        content: value
    ))
    return try makeSequence(fields)
}

private func makeOID(
    _ arcs: ContiguousArray<UInt64>
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 128)
    try writer.appendObjectIdentifier(arcs.span)
    return writer.finish()
}

private func makePositiveInteger(_ value: UInt64) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 16)
    try writer.appendPositiveInteger(value)
    return writer.finish()
}

private func makeSequence(_ elements: [OwnedBytes]) throws -> OwnedBytes {
    var content = ContiguousArray<UInt8>()
    for element in elements {
        content.reserveCapacity(content.count + element.count)
        var index = 0
        while index < element.count {
            content.append(element[index])
            index += 1
        }
    }
    return try makeElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: true,
            number: 16
        ),
        content: OwnedBytes(consuming: content)
    )
}

private func makeElement(
    tag: SwiftSSLASN1.DERTag,
    content: OwnedBytes
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: content.count + 16)
    try writer.append(tag: tag, content: content.span)
    return writer.finish()
}

private func makeElement(
    tag: SwiftSSLASN1.DERTag,
    content: ContiguousArray<UInt8>
) throws -> OwnedBytes {
    try makeElement(tag: tag, content: OwnedBytes(consuming: content))
}
