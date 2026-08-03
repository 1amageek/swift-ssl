import XCTest
import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto
@testable import SwiftSSLX509

final class OCSPResponseTests: XCTestCase {
    func testSHA1IdentifierKnownAnswer() {
        let input = ContiguousArray("abc".utf8)
        XCTAssertEqual(
            OCSPIdentifierHash.hash(input.span),
            ocspHex("a9993e364706816aba3e25717850c26c9cd0d89d")
        )
    }

    func testEvaluatesIssuerSignedResponseAsGood() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x71, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeOCSPCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeOCSPCertificate(serial: 7, publicKey: publicKey)
        let nonce = ContiguousArray<UInt8>([1, 3, 3, 7])
        let encoded = try makeOCSPResponse(
            certificateSerial: 7,
            issuerPublicKey: publicKey,
            status: .good,
            nonce: nonce,
            privateKey: privateKey
        )
        let response = try OCSPResponse(der: encoded.span)

        XCTAssertEqual(
            try response.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try ocspVerificationTime(),
                expectedNonce: nonce.span
            ),
            .good
        )
    }

    func testEvaluatesIssuerSignedResponseAsRevoked() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x72, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeOCSPCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeOCSPCertificate(serial: 7, publicKey: publicKey)
        let encoded = try makeOCSPResponse(
            certificateSerial: 7,
            issuerPublicKey: publicKey,
            status: .revoked,
            nonce: nil,
            privateKey: privateKey
        )
        let response = try OCSPResponse(der: encoded.span)

        XCTAssertEqual(
            try response.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try ocspVerificationTime()
            ),
            .revoked(at: try VerificationInstant(
                secondsSinceUnixEpoch: 1_735_689_600,
                nanoseconds: 0
            ))
        )
    }

    func testRejectsNonceMismatch() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x73, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeOCSPCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeOCSPCertificate(serial: 7, publicKey: publicKey)
        let encoded = try makeOCSPResponse(
            certificateSerial: 7,
            issuerPublicKey: publicKey,
            status: .good,
            nonce: [1, 2, 3],
            privateKey: privateKey
        )
        let response = try OCSPResponse(der: encoded.span)
        let unexpectedNonce = ContiguousArray<UInt8>([9, 9, 9])

        do {
            _ = try response.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try ocspVerificationTime(),
                expectedNonce: unexpectedNonce.span
            )
            XCTFail("mismatched OCSP nonce was accepted")
        } catch let error as OCSPResponseError {
            XCTAssertEqual(error, .nonceMismatch)
        }
    }

    func testRejectsModifiedResponseSignature() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x74, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeOCSPCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeOCSPCertificate(serial: 7, publicKey: publicKey)
        var encoded = try makeOCSPResponse(
            certificateSerial: 7,
            issuerPublicKey: publicKey,
            status: .good,
            nonce: nil,
            privateKey: privateKey
        )
        encoded[encoded.count - 1] ^= 1
        let response = try OCSPResponse(der: encoded.span)

        do {
            _ = try response.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try ocspVerificationTime()
            )
            XCTFail("modified OCSP signature was accepted")
        } catch let error as OCSPResponseError {
            XCTAssertEqual(error, .signature(.invalidSignature))
        }
    }

    func testReturnsSCTsOnlyAfterCertificateAssociatedEvaluation() throws {
        let privateKey = try Ed25519PrivateKey(
            seed: ContiguousArray<UInt8>(repeating: 0x75, count: 32).span
        )
        let publicKey = try privateKey.publicKey()
        let issuer = try makeOCSPCertificate(serial: 1, publicKey: publicKey)
        let leaf = try makeOCSPCertificate(serial: 7, publicKey: publicKey)
        let timestampList = ocspHex(
            "007700750020cf9f8b80b065601c1cf5d3c647f3200b80b5a9cf10cf592d4bd0a" +
            "959287a9c0000019b76daa80000000403004630440220725e0b0551d276be127902" +
            "35362bc22e5f39a474128bb90de1f2a97310081b47022024f6a369dcefde1a0780" +
            "75170b908507f46f6ead8ad68d23486c7dfe62de2c63"
        )
        let encoded = try makeOCSPResponse(
            certificateSerial: 7,
            issuerPublicKey: publicKey,
            status: .good,
            nonce: nil,
            signedCertificateTimestampList: timestampList,
            privateKey: privateKey
        )
        let response = try OCSPResponse(der: encoded.span)

        XCTAssertEqual(
            try response.evaluate(
                certificate: leaf,
                issuer: issuer,
                at: try ocspVerificationTime()
            ),
            .good
        )
        let timestamps = try response.signedCertificateTimestamps(
            certificate: leaf,
            issuer: issuer
        )
        XCTAssertEqual(timestamps?.timestamps.count, 1)
    }
}

private enum OCSPFixtureStatus {
    case good
    case revoked
}

private func makeOCSPResponse(
    certificateSerial: UInt64,
    issuerPublicKey: ContiguousArray<UInt8>,
    status: OCSPFixtureStatus,
    nonce: ContiguousArray<UInt8>?,
    signedCertificateTimestampList: ContiguousArray<UInt8>? = nil,
    privateKey: borrowing Ed25519PrivateKey
) throws -> ContiguousArray<UInt8> {
    let signatureAlgorithm = try ocspSequence([
        try ocspOID([1, 3, 101, 112]),
    ])
    let hashAlgorithm = try ocspSequence([
        try ocspOID([2, 16, 840, 1, 101, 3, 4, 2, 1]),
    ])
    let issuerName = try ocspSequence([])
    let issuerNameHash = try ocspSHA256(issuerName.span)
    let issuerKeyHash = try ocspSHA256(issuerPublicKey.span)
    let certificateIdentifier = try ocspSequence([
        hashAlgorithm,
        try ocspOctetString(issuerNameHash),
        try ocspOctetString(issuerKeyHash),
        try ocspInteger(certificateSerial),
    ])
    let certificateStatus: OwnedBytes
    switch status {
    case .good:
        certificateStatus = try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: false,
                number: 0
            ),
            content: OwnedBytes()
        )
    case .revoked:
        certificateStatus = try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 1
            ),
            content: try ocspGeneralizedTime("20250101000000Z")
        )
    }
    let nextUpdate = try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: true,
            number: 0
        ),
        content: try ocspGeneralizedTime("20350101000000Z")
    )
    let singleResponse = try ocspSequence([
        certificateIdentifier,
        certificateStatus,
        try ocspGeneralizedTime("20250101000000Z"),
        nextUpdate,
    ])
    var responseDataFields = [
        try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 1
            ),
            content: issuerName
        ),
        try ocspGeneralizedTime("20250101000000Z"),
        try ocspSequence([singleResponse]),
    ]
    var responseExtensions = [OwnedBytes]()
    if let nonce {
        let nonceValue = try ocspOctetString(nonce)
        let nonceExtension = try ocspSequence([
            try ocspOID([1, 3, 6, 1, 5, 5, 7, 48, 1, 2]),
            try ocspOctetString(ocspCopy(nonceValue)),
        ])
        responseExtensions.append(nonceExtension)
    }
    if let signedCertificateTimestampList {
        let encodedList = try ocspOctetString(
            signedCertificateTimestampList
        )
        responseExtensions.append(try ocspSequence([
            try ocspOID([1, 3, 6, 1, 4, 1, 11_129, 2, 4, 5]),
            try ocspOctetString(ocspCopy(encodedList)),
        ]))
    }
    if !responseExtensions.isEmpty {
        let extensions = try ocspSequence(responseExtensions)
        responseDataFields.append(try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 1
            ),
            content: extensions
        ))
    }
    let responseData = try ocspSequence(responseDataFields)
    let signature = try Ed25519.sign(
        message: responseData.span,
        using: privateKey
    )
    var signatureContent = ContiguousArray<UInt8>([0])
    signatureContent.append(contentsOf: signature)
    let basicResponse = try ocspSequence([
        responseData,
        signatureAlgorithm,
        try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 3
            ),
            content: OwnedBytes(consuming: signatureContent)
        ),
    ])
    let responseBytes = try ocspSequence([
        try ocspOID([1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
        try ocspOctetString(ocspCopy(basicResponse)),
    ])
    let encoded = try ocspSequence([
        try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 10
            ),
            content: OwnedBytes(consuming: [0])
        ),
        try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 0
            ),
            content: responseBytes
        ),
    ])
    return ocspCopy(encoded)
}

private func makeOCSPCertificate(
    serial: UInt64,
    publicKey: ContiguousArray<UInt8>
) throws -> X509Certificate {
    let algorithm = try ocspSequence([try ocspOID([1, 3, 101, 112])])
    let name = try ocspSequence([])
    var publicKeyContent = ContiguousArray<UInt8>([0])
    publicKeyContent.append(contentsOf: publicKey)
    let subjectPublicKeyInfo = try ocspSequence([
        algorithm,
        try ocspElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: 3
            ),
            content: OwnedBytes(consuming: publicKeyContent)
        ),
    ])
    let version = try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .contextSpecific,
            isConstructed: true,
            number: 0
        ),
        content: try ocspInteger(2)
    )
    let validity = try ocspSequence([
        try ocspUTCTime("250101000000Z"),
        try ocspUTCTime("350101000000Z"),
    ])
    let tbs = try ocspSequence([
        version,
        try ocspInteger(serial),
        algorithm,
        name,
        validity,
        name,
        subjectPublicKeyInfo,
    ])
    let signature = try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 3
        ),
        content: OwnedBytes(
            consuming: ContiguousArray<UInt8>(repeating: 0, count: 65)
        )
    )
    let encoded = try ocspSequence([tbs, algorithm, signature])
    return try X509Certificate(der: encoded.span)
}

private func ocspVerificationTime() throws -> VerificationInstant {
    try VerificationInstant(
        secondsSinceUnixEpoch: 1_767_225_600,
        nanoseconds: 0
    )
}

private func ocspSHA256(
    _ input: Span<UInt8>
) throws -> ContiguousArray<UInt8> {
    var digest = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var output = digest.mutableSpan
    try SHA256.hash(input, into: &output)
    return digest
}

private func ocspGeneralizedTime(_ text: String) throws -> OwnedBytes {
    try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 24
        ),
        content: OwnedBytes(consuming: ContiguousArray(text.utf8))
    )
}

private func ocspUTCTime(_ text: String) throws -> OwnedBytes {
    try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 23
        ),
        content: OwnedBytes(consuming: ContiguousArray(text.utf8))
    )
}

private func ocspInteger(_ value: UInt64) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 16)
    try writer.appendPositiveInteger(value)
    return writer.finish()
}

private func ocspOID(
    _ objectIdentifier: ContiguousArray<UInt64>
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: 64)
    try writer.appendObjectIdentifier(objectIdentifier.span)
    return writer.finish()
}

private func ocspOctetString(
    _ bytes: ContiguousArray<UInt8>
) throws -> OwnedBytes {
    try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 4
        ),
        content: OwnedBytes(consuming: bytes)
    )
}

private func ocspSequence(_ elements: [OwnedBytes]) throws -> OwnedBytes {
    var content = ContiguousArray<UInt8>()
    for element in elements {
        content.append(contentsOf: ocspCopy(element))
    }
    return try ocspElement(
        tag: SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: true,
            number: 16
        ),
        content: OwnedBytes(consuming: content)
    )
}

private func ocspElement(
    tag: SwiftSSLASN1.DERTag,
    content: OwnedBytes
) throws -> OwnedBytes {
    var writer = try DERWriter(maximumByteCount: content.count + 16)
    try writer.append(tag: tag, content: content.span)
    return writer.finish()
}

private func ocspCopy(_ bytes: borrowing OwnedBytes) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
        result.append(bytes[index])
        index += 1
    }
    return result
}

private func ocspHex(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = value.startIndex
    while index < value.endIndex {
        let next = value.index(index, offsetBy: 2)
        result.append(UInt8(value[index..<next], radix: 16)!)
        index = next
    }
    return result
}
