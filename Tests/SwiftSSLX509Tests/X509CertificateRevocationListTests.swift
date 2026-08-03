import XCTest
import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

final class X509CertificateRevocationListTests: XCTestCase {
    func testEvaluatesSignedCurrentCRLAsRevoked() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x31, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeCRLCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeCRLCertificate(serial: 7, publicKey: publicKey)
        let encoded = try makeCRL(
            revokedSerials: [7],
            privateKey: privateKey
        )
        let crl = try X509CertificateRevocationList(der: encoded.span)
        let verificationTime = try VerificationInstant(
            secondsSinceUnixEpoch: 1_767_225_600,
            nanoseconds: 0
        )

        XCTAssertEqual(
            try crl.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: verificationTime
            ),
            .revoked(at: try VerificationInstant(
                secondsSinceUnixEpoch: 1_735_689_600,
                nanoseconds: 0
            ))
        )
    }

    func testEvaluatesUnlistedSerialAsGood() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x42, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeCRLCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeCRLCertificate(serial: 8, publicKey: publicKey)
        let encoded = try makeCRL(
            revokedSerials: [7],
            privateKey: privateKey
        )
        let crl = try X509CertificateRevocationList(der: encoded.span)

        XCTAssertEqual(
            try crl.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try VerificationInstant(
                    secondsSinceUnixEpoch: 1_767_225_600,
                    nanoseconds: 0
                )
            ),
            .good
        )
    }

    func testRejectsModifiedCRLSignature() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x53, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeCRLCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeCRLCertificate(serial: 7, publicKey: publicKey)
        var encoded = try makeCRL(
            revokedSerials: [7],
            privateKey: privateKey
        )
        encoded[encoded.count - 1] ^= 1
        let crl = try X509CertificateRevocationList(der: encoded.span)

        do {
            _ = try crl.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try VerificationInstant(
                    secondsSinceUnixEpoch: 1_767_225_600,
                    nanoseconds: 0
                )
            )
            XCTFail("modified CRL signature was accepted")
        } catch let error as X509CertificateRevocationListError {
            XCTAssertEqual(error, .signature(.invalidSignature))
        }
    }

    func testRejectsExpiredCRL() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x64, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeCRLCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeCRLCertificate(serial: 7, publicKey: publicKey)
        let encoded = try makeCRL(
            revokedSerials: [7],
            privateKey: privateKey
        )
        let crl = try X509CertificateRevocationList(der: encoded.span)

        do {
            _ = try crl.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try VerificationInstant(
                    secondsSinceUnixEpoch: 2_082_758_400,
                    nanoseconds: 0
                )
            )
            XCTFail("expired CRL was accepted")
        } catch let error as X509CertificateRevocationListError {
            XCTAssertEqual(error, .expired)
        }
    }

    func testHardFailRequiresEvidenceAndSoftFailAllowsAbsence() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x75, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeCRLCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeCRLCertificate(serial: 7, publicKey: publicKey)
        let path = ContiguousArray([leaf, issuer])
        let noEvidence = ContiguousArray<X509RevocationEvidence>()
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_767_225_600,
            nanoseconds: 0
        )
        let hardFail = RFC5280RevocationEvaluator(policy: .init(
            mode: .hardFail,
            checksIntermediates: false
        ))
        let softFail = RFC5280RevocationEvaluator(policy: .init(
            mode: .softFail,
            checksIntermediates: false
        ))

        do {
            try hardFail.evaluate(
                path: path,
                evidence: noEvidence,
                at: instant
            )
            XCTFail("hard-fail revocation policy accepted missing evidence")
        } catch let error as X509RevocationError {
            XCTAssertEqual(error, .evidenceRequired(certificateIndex: 0))
        }
        XCTAssertNoThrow(try softFail.evaluate(
            path: path,
            evidence: noEvidence,
            at: instant
        ))
    }
}

private func makeCRLCertificate(
    serial: UInt64,
    publicKey: ContiguousArray<UInt8>
) throws -> X509Certificate {
    let algorithm = try crlSequence([try crlOID([1, 3, 101, 112])])
    let version = try crlElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: true,
            number: 0
        ),
        content: try crlInteger(2)
    )
    let emptyName = try crlSequence([])
    let validity = try crlSequence([
        try crlTime("250101000000Z"),
        try crlTime("350101000000Z"),
    ])
    var publicKeyContent = ContiguousArray<UInt8>([0])
    publicKeyContent.append(contentsOf: publicKey)
    let subjectPublicKeyInfo = try crlSequence([
        algorithm,
        try crlElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 3
            ),
            content: OwnedBytes(consuming: publicKeyContent)
        ),
    ])
    let tbs = try crlSequence([
        version,
        try crlInteger(serial),
        algorithm,
        emptyName,
        validity,
        emptyName,
        subjectPublicKeyInfo,
    ])
    let placeholderSignature = try crlElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 3
        ),
        content: OwnedBytes(
            consuming: ContiguousArray<UInt8>(repeating: 0, count: 65)
        )
    )
    let encoded = try crlSequence([tbs, algorithm, placeholderSignature])
    return try X509Certificate(der: encoded.span)
}

private func makeCRL(
    revokedSerials: [UInt64],
    privateKey: borrowing Ed25519PrivateKey
) throws -> ContiguousArray<UInt8> {
    let algorithm = try crlSequence([try crlOID([1, 3, 101, 112])])
    var revokedEntries = [OwnedBytes]()
    for serial in revokedSerials {
        revokedEntries.append(try crlSequence([
            try crlInteger(serial),
            try crlTime("250101000000Z"),
        ]))
    }
    let revoked = try crlSequence(revokedEntries)
    let tbs = try crlSequence([
        try crlInteger(1),
        algorithm,
        try crlSequence([]),
        try crlTime("250101000000Z"),
        try crlTime("350101000000Z"),
        revoked,
    ])
    let signature = try Ed25519.sign(
        message: tbs.span,
        using: privateKey
    )
    var signatureContent = ContiguousArray<UInt8>([0])
    signatureContent.append(contentsOf: signature)
    let signatureValue = try crlElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 3
        ),
        content: OwnedBytes(consuming: signatureContent)
    )
    let encoded = try crlSequence([tbs, algorithm, signatureValue])
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(encoded.count)
    var index = 0
    while index < encoded.count {
        result.append(encoded[index])
        index += 1
    }
    return result
}

private func crlTime(_ text: String) throws -> OwnedBytes {
    try crlElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 23
        ),
        content: OwnedBytes(consuming: ContiguousArray(text.utf8))
    )
}

private func crlInteger(_ value: UInt64) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 16)
    try writer.appendPositiveInteger(value)
    return writer.finish()
}

private func crlOID(
    _ objectIdentifier: ContiguousArray<UInt64>
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 64)
    try writer.appendObjectIdentifier(objectIdentifier.span)
    return writer.finish()
}

private func crlSequence(_ elements: [OwnedBytes]) throws -> OwnedBytes {
    var content = ContiguousArray<UInt8>()
    for element in elements {
        content.reserveCapacity(content.count + element.count)
        var index = 0
        while index < element.count {
            content.append(element[index])
            index += 1
        }
    }
    return try crlElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: true,
            number: 16
        ),
        content: OwnedBytes(consuming: content)
    )
}

private func crlElement(
    tag: SwiftSSLASN1.DERTag,
    content: OwnedBytes
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: content.count + 16)
    try writer.append(tag: tag, content: content.span)
    return writer.finish()
}
