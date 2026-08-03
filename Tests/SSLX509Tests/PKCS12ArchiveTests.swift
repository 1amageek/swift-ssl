import XCTest
import SSLCore
import SSLASN1
import SSLX509

final class PKCS12ArchiveTests: XCTestCase {
    func testModernIdentityRoundTripPreservesKeyAndCertificateOrder() throws {
        let privateKeyDER = makeEd25519PrivateKeyInfo()
        let leafDER = makeCertificate(
            publicKey: Self.ed25519PublicKey,
            signatureByte: 0x02
        )
        let issuerDER = makeCertificate(
            publicKey: Self.ed25519PublicKey,
            signatureByte: 0x03
        )
        let password: ContiguousArray<UInt8> = [
            0x70, 0x6B, 0x63, 0x73, 0x31, 0x32,
        ]
        let privateKey = try PrivateKeyInfo(der: privateKeyDER.span)
        let codec = ModernPKCS12IdentityCodec(
            encryption: try makeEncryptionProfile()
        )
        let archive = try codec.seal(
            privateKey: privateKey,
            certificates: [
                CertificateBytes(copying: leafDER.span),
                CertificateBytes(copying: issuerDER.span),
            ],
            password: password.span,
            using: PKCS12FixedEntropy()
        )
        XCTAssertEqual(archive.certificateCount, 2)

        let encoded = archive.withDERBytes { copy($0) }
        let reparsed = try PKCS12Archive(der: encoded.span)
        let identity = try codec.open(reparsed, password: password.span)
        XCTAssertEqual(identity.certificateCount, 2)
        XCTAssertEqual(identity.privateKeyAlgorithm, .ed25519)
        let reopenedKeyDER = identity.withPrivateKeyDER { copy($0) }
        XCTAssertEqual(reopenedKeyDER, privateKeyDER)
        let reopenedLeaf = try identity.certificate(at: 0)
        let reopenedIssuer = try identity.certificate(at: 1)
        XCTAssertEqual(copy(reopenedLeaf.span), leafDER)
        XCTAssertEqual(copy(reopenedIssuer.span), issuerDER)
    }

    func testWrongPasswordFailsAuthenticatedDecryption() throws {
        let password: ContiguousArray<UInt8> = [0x67, 0x6F, 0x6F, 0x64]
        let wrongPassword: ContiguousArray<UInt8> = [0x62, 0x61, 0x64]
        let codec = ModernPKCS12IdentityCodec(
            encryption: try makeEncryptionProfile()
        )
        let archive = try makeArchive(codec: codec, password: password)

        do {
            let identity = try codec.open(
                archive,
                password: wrongPassword.span
            )
            _ = consume identity
            XCTFail("an incorrect PKCS12 password authenticated")
        } catch {
            XCTAssertEqual(
                error as? PKCS12IdentityError,
                .encryption(.authenticationFailed)
            )
        }
    }

    func testRejectsMismatchedLeafCertificateBeforeEncryption() throws {
        let privateKeyDER = makeEd25519PrivateKeyInfo()
        let privateKey = try PrivateKeyInfo(der: privateKeyDER.span)
        var mismatchedPublicKey = Self.ed25519PublicKey
        mismatchedPublicKey[0] ^= 0x01
        let certificateDER = makeCertificate(
            publicKey: mismatchedPublicKey,
            signatureByte: 0x02
        )
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let codec = ModernPKCS12IdentityCodec(
            encryption: try makeEncryptionProfile()
        )

        do {
            _ = try codec.seal(
                privateKey: privateKey,
                certificates: [CertificateBytes(copying: certificateDER.span)],
                password: password.span,
                using: PKCS12FixedEntropy()
            )
            XCTFail("a mismatched PKCS12 identity was accepted")
        } catch {
            XCTAssertEqual(
                error as? PKCS12IdentityError,
                .keyPairMismatch
            )
        }
    }

    func testRejectsUnsupportedPrivateKeyAlgorithm() throws {
        let privateKeyDER = makeX25519PrivateKeyInfo()
        let privateKey = try PrivateKeyInfo(der: privateKeyDER.span)
        let certificateDER = makeCertificate(
            publicKey: Self.ed25519PublicKey,
            signatureByte: 0x02
        )
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let codec = ModernPKCS12IdentityCodec(
            encryption: try makeEncryptionProfile()
        )

        do {
            _ = try codec.seal(
                privateKey: privateKey,
                certificates: [CertificateBytes(copying: certificateDER.span)],
                password: password.span,
                using: PKCS12FixedEntropy()
            )
            XCTFail("an unsupported PKCS12 private-key algorithm was accepted")
        } catch {
            XCTAssertEqual(
                error as? PKCS12IdentityError,
                .unsupportedPrivateKeyAlgorithm
            )
        }
    }

    func testRejectsMacDataAndOutOfBoundsCertificateAccess() throws {
        let password: ContiguousArray<UInt8> = [0x70, 0x61, 0x73, 0x73]
        let codec = ModernPKCS12IdentityCodec(
            encryption: try makeEncryptionProfile()
        )
        let archive = try makeArchive(codec: codec, password: password)

        do {
            try archive.withCertificateDER(at: 1) { _ in () }
            XCTFail("an out-of-bounds PKCS12 certificate was returned")
        } catch {
            XCTAssertEqual(
                error as? PKCS12ArchiveError,
                .certificateIndexOutOfBounds(index: 1, count: 1)
            )
        }

        let withMacData = try appendEmptyMacData(to: archive)
        do {
            _ = try PKCS12Archive(der: withMacData.span)
            XCTFail("PKCS12 MacData was accepted by the modern profile")
        } catch {
            XCTAssertEqual(
                error as? PKCS12ArchiveError,
                .macDataUnsupported
            )
        }
    }

    private func makeArchive(
        codec: ModernPKCS12IdentityCodec,
        password: ContiguousArray<UInt8>
    ) throws -> PKCS12Archive {
        let privateKeyDER = makeEd25519PrivateKeyInfo()
        let certificateDER = makeCertificate(
            publicKey: Self.ed25519PublicKey,
            signatureByte: 0x02
        )
        let privateKey = try PrivateKeyInfo(der: privateKeyDER.span)
        return try codec.seal(
            privateKey: privateKey,
            certificates: [CertificateBytes(copying: certificateDER.span)],
            password: password.span,
            using: PKCS12FixedEntropy()
        )
    }

    private func makeEncryptionProfile() throws -> PBES2AES256GCM {
        try PBES2AES256GCM(
            encryptionIterations: 100_000,
            minimumAcceptedIterations: 100_000,
            maximumAcceptedIterations: 1_000_000
        )
    }

    private func appendEmptyMacData(
        to archive: borrowing PKCS12Archive
    ) throws -> ContiguousArray<UInt8> {
        try archive.withDERBytes { encoded throws -> ContiguousArray<UInt8> in
            var budget = try ParsingBudget(
                limits: PKCS12Archive.defaultParsingLimits,
                inputByteCount: encoded.count
            )
            var cursor = DERCursor(encoded)
            let root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()

            var bodyCursor = DERCursor(root.contentBytes)
            var bodyWriter = try DERWriter(
                maximumByteCount: encoded.count + 16
            )
            while !bodyCursor.isAtEnd {
                let element = try bodyCursor.readElement(using: &budget)
                try bodyWriter.append(
                    tag: element.tag,
                    content: element.contentBytes
                )
            }
            let empty = ContiguousArray<UInt8>()
            try bodyWriter.append(
                tag: DERTag(
                    tagClass: .universal,
                    isConstructed: true,
                    number: 16
                ),
                content: empty.span
            )
            let body = bodyWriter.finish()
            var writer = try DERWriter(
                maximumByteCount: encoded.count + 16
            )
            try writer.append(tag: root.tag, content: body.span)
            return copy(writer.finish().span)
        }
    }

    private func makeEd25519PrivateKeyInfo() -> ContiguousArray<UInt8> {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2E,
            0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20,
        ]
        der.append(contentsOf: Self.ed25519Seed)
        return der
    }

    private func makeX25519PrivateKeyInfo() -> ContiguousArray<UInt8> {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2C,
            0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x04, 0x20,
        ]
        der.append(contentsOf: repeatElement(0x5A, count: 32))
        return der
    }

    private func makeCertificate(
        publicKey: ContiguousArray<UInt8>,
        signatureByte: UInt8
    ) -> ContiguousArray<UInt8> {
        var tbs: ContiguousArray<UInt8> = [
            0x30, 0x5A,
            0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x30, 0x00,
            0x30, 0x1E,
            0x17, 0x0D,
        ]
        tbs.append(contentsOf: ContiguousArray("240101000000Z".utf8))
        tbs.append(contentsOf: [0x17, 0x0D])
        tbs.append(contentsOf: ContiguousArray("250101000000Z".utf8))
        tbs.append(contentsOf: [
            0x30, 0x00,
            0x30, 0x2A,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x21, 0x00,
        ])
        tbs.append(contentsOf: publicKey)

        var result: ContiguousArray<UInt8> = [0x30, 0x68]
        result.append(contentsOf: tbs)
        result.append(contentsOf: [
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x03, 0x00, 0x01, signatureByte,
        ])
        return result
    }

    private func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }

    private static let ed25519Seed: ContiguousArray<UInt8> = [
        0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60,
        0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C, 0xC4,
        0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19,
        0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE, 0x7F, 0x60,
    ]
    private static let ed25519PublicKey: ContiguousArray<UInt8> = [
        0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7,
        0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
        0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25,
        0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
    ]
}

private struct PKCS12FixedEntropy: EntropySource {
    func fill(
        _ destination: inout MutableSpan<UInt8>
    ) throws(EntropyError) {
        let base: UInt8
        switch destination.count {
        case EncryptedPrivateKeyInfo.saltByteCount:
            base = 0x40
        case EncryptedPrivateKeyInfo.nonceByteCount:
            base = 0x80
        default:
            throw .requestTooLarge(limit: 16, requested: destination.count)
        }
        var index = 0
        while index < destination.count {
            destination[index] = base &+ UInt8(index)
            index += 1
        }
    }
}
