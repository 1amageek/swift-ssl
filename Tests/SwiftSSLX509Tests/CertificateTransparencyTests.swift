import XCTest
import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLX509

final class CertificateTransparencyTests: XCTestCase {
    func testParsesAndVerifiesRFC6962X509Entry() throws {
        let certificate = try X509Certificate(der: certificateDER().span)
        let timestamps = try SignedCertificateTimestampList(
            encoded: signedCertificateTimestampList().span
        )
        let log = try makeLog()
        let verifier = RFC6962CertificateTransparencyVerifier(
            policy: CertificateTransparencyPolicy(
                minimumValidSCTCount: 1,
                minimumDistinctOperatorCount: 1
            )
        )

        XCTAssertEqual(timestamps.timestamps.count, 1)
        XCTAssertEqual(timestamps.timestamps[0].logIdentifier, log.logIdentifier)
        XCTAssertNoThrow(try verifier.verify(
            certificate: certificate,
            timestamps: timestamps,
            logs: [log],
            at: instant(1_767_312_000)
        ))
    }

    func testRejectsModifiedSCTSignature() throws {
        let certificate = try X509Certificate(der: certificateDER().span)
        var encoded = signedCertificateTimestampList()
        encoded[encoded.count - 1] ^= 1
        let timestamps = try SignedCertificateTimestampList(encoded: encoded.span)
        let log = try makeLog()
        let verifier = RFC6962CertificateTransparencyVerifier(
            policy: CertificateTransparencyPolicy(
                minimumValidSCTCount: 1,
                minimumDistinctOperatorCount: 1
            )
        )

        XCTAssertThrowsError(try verifier.verify(
            certificate: certificate,
            timestamps: timestamps,
            logs: [log],
            at: instant(1_767_312_000)
        )) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .insufficientValidSCTs(required: 1, actual: 0)
            )
        }
    }

    func testEnforcesSCTThreshold() throws {
        let certificate = try X509Certificate(der: certificateDER().span)
        let timestamps = try SignedCertificateTimestampList(
            encoded: signedCertificateTimestampList().span
        )
        let verifier = RFC6962CertificateTransparencyVerifier(
            policy: CertificateTransparencyPolicy(
                minimumValidSCTCount: 2,
                minimumDistinctOperatorCount: 1
            )
        )

        XCTAssertThrowsError(try verifier.verify(
            certificate: certificate,
            timestamps: timestamps,
            logs: [try makeLog()],
            at: instant(1_767_312_000)
        )) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .insufficientValidSCTs(required: 2, actual: 1)
            )
        }
    }

    func testRejectsMalformedListLengthAndUnsupportedVersion() throws {
        var invalidLength = signedCertificateTimestampList()
        invalidLength[1] &-= 1
        XCTAssertThrowsError(
            try SignedCertificateTimestampList(encoded: invalidLength.span)
        ) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .invalidListLength
            )
        }

        var unsupportedVersion = signedCertificateTimestampList()
        unsupportedVersion[4] = 1
        XCTAssertThrowsError(
            try SignedCertificateTimestampList(encoded: unsupportedVersion.span)
        ) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .unsupportedVersion(1)
            )
        }
    }

    func testReconstructsPrecertificateByRemovingEmbeddedSCTExtension() throws {
        let baseDER = certificateDER()
        let baseCertificate = try X509Certificate(der: baseDER.span)
        let embeddedDER = try certificateWithEmbeddedSCT(
            baseCertificateDER: baseDER.span,
            timestampList: signedCertificateTimestampList().span
        )
        let embeddedCertificate = try X509Certificate(der: embeddedDER.span)
        let precertificate = try RFC6962Precertificate(
            reconstructing: embeddedCertificate,
            issuerPublicKey: baseCertificate.subjectPublicKeyInfo
        )

        XCTAssertEqual(
            precertificate.timestamps,
            try SignedCertificateTimestampList(
                encoded: signedCertificateTimestampList().span
            )
        )
        let originalTBS = baseCertificate.withTBSCertificateBytes {
            copy($0)
        }
        let reconstructedTBS = precertificate.withTBSCertificateBytes {
            copy($0)
        }
        XCTAssertEqual(reconstructedTBS, originalTBS)
    }

    func testPrecertificateRequiresEmbeddedSCTExtension() throws {
        let certificate = try X509Certificate(der: certificateDER().span)
        XCTAssertThrowsError(
            try RFC6962Precertificate(
                reconstructing: certificate,
                issuerPublicKey: certificate.subjectPublicKeyInfo
            )
        ) { error in
            XCTAssertEqual(
                error as? CertificateTransparencyError,
                .missingEmbeddedSCTExtension
            )
        }
    }

    func testVerifiesRFC6962PrecertificateEntry() throws {
        let baseDER = certificateDER()
        let baseCertificate = try X509Certificate(der: baseDER.span)
        let embeddedDER = try certificateWithEmbeddedSCT(
            baseCertificateDER: baseDER.span,
            timestampList: precertificateTimestampList().span
        )
        let embeddedCertificate = try X509Certificate(der: embeddedDER.span)
        let precertificate = try RFC6962Precertificate(
            reconstructing: embeddedCertificate,
            issuerPublicKey: baseCertificate.subjectPublicKeyInfo
        )
        let log = try CertificateTransparencyLog(
            publicKey: SubjectPublicKeyInfo(
                der: precertificateLogSPKI().span
            ),
            operatorIdentifier: 11,
            validFrom: instant(1_735_689_600),
            validUntil: instant(2_051_222_400)
        )
        let verifier = RFC6962CertificateTransparencyVerifier(
            policy: CertificateTransparencyPolicy(
                minimumValidSCTCount: 1,
                minimumDistinctOperatorCount: 1
            )
        )

        XCTAssertNoThrow(try verifier.verify(
            precertificate: precertificate,
            logs: [log],
            at: instant(1_767_312_000)
        ))
    }

    private func makeLog() throws -> CertificateTransparencyLog {
        let publicKey = try SubjectPublicKeyInfo(der: logSPKI().span)
        return try CertificateTransparencyLog(
            publicKey: publicKey,
            operatorIdentifier: 7,
            validFrom: instant(1_735_689_600),
            validUntil: instant(2_051_222_400)
        )
    }

    private func instant(_ seconds: Int64) throws -> VerificationInstant {
        try VerificationInstant(
            secondsSinceUnixEpoch: seconds,
            nanoseconds: 0
        )
    }

    private func certificateDER() -> ContiguousArray<UInt8> {
        bytes(
            "3082016930820110a003020102020107300a06082a8648ce3d04030230223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d" +
            "3235303130313030303030305a170d3335303130313030303030305a30223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013" +
            "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e" +
            "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f" +
            "9e162bce33576b315ececbb6406837bf51f5a3373035300f0603551d130101ff0405" +
            "30030101ff30220603551d11041b3019821773776966742d73736c2d65636473612e" +
            "6578616d706c65300a06082a8648ce3d040302034700304402207d64b4f0d8d41a49" +
            "720e591dc1844556462cd8beb44558fa9f63156a76f2c6cc022063756eb89655ab0b" +
            "0b04032d184382dd99e0be5ce5cacc66374a36dc83f7ac23"
        )
    }

    private func logSPKI() -> ContiguousArray<UInt8> {
        bytes(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000428d9cd4e58d474" +
            "02834cb8379ddae71f3aabf55676cb4dbe2ba594ecb5fb0525a74d57f208725c37c2" +
            "11211d68d7d5b557d2be1b0421fe29b9f6824aa6697431"
        )
    }

    private func signedCertificateTimestampList() -> ContiguousArray<UInt8> {
        bytes(
            "007700750020cf9f8b80b065601c1cf5d3c647f3200b80b5a9cf10cf592d4bd0a959" +
            "287a9c0000019b76daa80000000403004630440220725e0b0551d276be12790235362b" +
            "c22e5f39a474128bb90de1f2a97310081b47022024f6a369dcefde1a078075170b90" +
            "8507f46f6ead8ad68d23486c7dfe62de2c63"
        )
    }

    private func precertificateLogSPKI() -> ContiguousArray<UInt8> {
        bytes(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000484363aaf250bde" +
            "3b2798e12df2fee85e182113a3a1ff6e07c7db568601e6bf84b7f35b42ea176f8e" +
            "4170f2a1a88168de663e97c7d9d24ac21727673767fcf72a"
        )
    }

    private func precertificateTimestampList() -> ContiguousArray<UInt8> {
        bytes(
            "0079007700f00e4cf433cc6a37959bcb25797cd32fcdbad076e5e41f661da36d3f" +
            "1255ab2a0000019b7c010400000004030048304602210095df13a83306c4d1ef37" +
            "77df1a3c9ec85304fa4c87ef92b06998457e5fa71d6a022100c576a7d772bf088b" +
            "e3482c0f1c74f073913807848f222d7fcd0a59d8aa9fa661"
        )
    }

    private func certificateWithEmbeddedSCT(
        baseCertificateDER: Span<UInt8>,
        timestampList: Span<UInt8>
    ) throws -> OwnedBytes {
        var budget = try ParsingBudget(
            limits: X509Certificate.defaultParsingLimits,
            inputByteCount: baseCertificateDER.count
        )
        var certificateCursor = DERCursor(baseCertificateDER)
        let certificate = try certificateCursor.readElement(using: &budget)
        try certificateCursor.requireFullyConsumed()
        var certificateBody = DERCursor(certificate.contentBytes)
        let tbs = try certificateBody.readElement(using: &budget)
        let algorithm = try certificateBody.readElement(using: &budget)
        let signature = try certificateBody.readElement(using: &budget)
        try certificateBody.requireFullyConsumed()

        let embeddedExtension = try makeEmbeddedSCTExtension(timestampList)
        var rebuiltTBSContent = ContiguousArray<UInt8>()
        rebuiltTBSContent.reserveCapacity(
            tbs.contentBytes.count + embeddedExtension.count + 8
        )
        var tbsBody = DERCursor(tbs.contentBytes)
        var foundExtensions = false
        while !tbsBody.isAtEnd {
            let field = try tbsBody.readElement(using: &budget)
            if field.tag == SwiftSSLASN1.DERTag(
                tagClass: .contextSpecific,
                isConstructed: true,
                number: 3
            ) {
                var explicit = DERCursor(field.contentBytes)
                let sequence = try explicit.readElement(using: &budget)
                try explicit.requireFullyConsumed()
                var extensionsContent = copy(sequence.contentBytes)
                append(embeddedExtension.span, to: &extensionsContent)
                let rebuiltSequence = try makeDERElement(
                    tag: SwiftSSLASN1.DERTag(
                        tagClass: .universal,
                        isConstructed: true,
                        number: 16
                    ),
                    content: extensionsContent.span
                )
                let rebuiltExplicit = try makeDERElement(
                    tag: field.tag,
                    content: rebuiltSequence.span
                )
                append(rebuiltExplicit.span, to: &rebuiltTBSContent)
                foundExtensions = true
            } else {
                append(field.encodedBytes, to: &rebuiltTBSContent)
            }
        }
        guard foundExtensions else {
            throw CertificateTransparencyError.invalidPrecertificate
        }

        let rebuiltTBS = try makeDERElement(
            tag: tbs.tag,
            content: rebuiltTBSContent.span
        )
        var rebuiltCertificateContent = ContiguousArray<UInt8>()
        rebuiltCertificateContent.reserveCapacity(
            rebuiltTBS.count + algorithm.encodedBytes.count
                + signature.encodedBytes.count
        )
        append(rebuiltTBS.span, to: &rebuiltCertificateContent)
        append(algorithm.encodedBytes, to: &rebuiltCertificateContent)
        append(signature.encodedBytes, to: &rebuiltCertificateContent)
        return try makeDERElement(
            tag: certificate.tag,
            content: rebuiltCertificateContent.span
        )
    }

    private func makeEmbeddedSCTExtension(
        _ timestampList: Span<UInt8>
    ) throws -> OwnedBytes {
        let octetStringTag = SwiftSSLASN1.DERTag(
            tagClass: .universal,
            isConstructed: false,
            number: 4
        )
        let embeddedList = try makeDERElement(
            tag: octetStringTag,
            content: timestampList
        )
        var oidWriter = try DERWriter(maximumByteCount: 32)
        let oid: ContiguousArray<UInt64> = [
            1, 3, 6, 1, 4, 1, 11_129, 2, 4, 2,
        ]
        try oidWriter.appendObjectIdentifier(oid.span)
        let encodedOID = oidWriter.finish()
        let extensionValue = try makeDERElement(
            tag: octetStringTag,
            content: embeddedList.span
        )
        var extensionContent = ContiguousArray<UInt8>()
        extensionContent.reserveCapacity(encodedOID.count + extensionValue.count)
        append(encodedOID.span, to: &extensionContent)
        append(extensionValue.span, to: &extensionContent)
        return try makeDERElement(
            tag: SwiftSSLASN1.DERTag(
                tagClass: .universal,
                isConstructed: true,
                number: 16
            ),
            content: extensionContent.span
        )
    }

    private func makeDERElement(
        tag: SwiftSSLASN1.DERTag,
        content: Span<UInt8>
    ) throws -> OwnedBytes {
        var writer = try DERWriter(
            maximumByteCount: content.count + 16,
            minimumCapacity: content.count + 8
        )
        try writer.append(tag: tag, content: content)
        return writer.finish()
    }

    private func copy(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(source.count)
        append(source, to: &result)
        return result
    }

    private func append(
        _ source: Span<UInt8>,
        to destination: inout ContiguousArray<UInt8>
    ) {
        var index = 0
        while index < source.count {
            destination.append(source[index])
            index += 1
        }
    }

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                preconditionFailure("fixture contains non-hexadecimal data")
            }
            result.append(byte)
            index = next
        }
        return result
    }
}
