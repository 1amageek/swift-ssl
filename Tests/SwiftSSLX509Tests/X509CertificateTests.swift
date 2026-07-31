import XCTest
import SwiftSSLCore
import SwiftSSLX509

final class X509CertificateTests: XCTestCase {
    func testParsesCertificateStructureAndRetainsRanges() throws {
        let certificate = makeCertificate()
        let parsed = try X509Certificate(der: certificate.span)
        XCTAssertEqual(parsed.version, 0)
        XCTAssertEqual(copy(parsed.serialNumber.span), [1])
        XCTAssertEqual(parsed.signatureAlgorithm.objectIdentifier, [1, 3, 101, 112])
        XCTAssertEqual(parsed.subjectPublicKeyInfo.algorithm, .x25519)
        XCTAssertEqual(parsed.validity.notBefore, "240101000000Z")
        XCTAssertEqual(parsed.validity.notAfter, "250101000000Z")
        let inside = try VerificationInstant(secondsSinceUnixEpoch: 1_704_067_200, nanoseconds: 0)
        let outside = try VerificationInstant(secondsSinceUnixEpoch: 1_735_689_601, nanoseconds: 0)
        XCTAssertTrue(parsed.validity.contains(inside))
        XCTAssertFalse(parsed.validity.contains(outside))
        var tbsByteCount = 0
        try parsed.withTBSCertificateBytes { tbs in
            tbsByteCount = tbs.count
        }
        XCTAssertEqual(tbsByteCount, 92)
        try parsed.withSignatureBytes { signature in
            XCTAssertEqual(copy(signature), [1, 2])
        }
    }

    func testRejectsInvalidCalendarDate() throws {
        var certificate = makeCertificate()
        let marker = Array("240101000000Z".utf8)
        guard let start = find(marker, in: certificate) else {
            XCTFail("fixture date was not found")
            return
        }
        certificate[start + 2] = 0x33
        do {
            _ = try X509Certificate(der: certificate.span)
            XCTFail("invalid calendar date was accepted")
        } catch {
            XCTAssertEqual(error, .invalidValidity)
        }
    }

    func testVerifiesEd25519CertificateSignature() throws {
        let certificate = makeSignedEd25519Certificate()
        let parsed: X509Certificate
        do {
            parsed = try X509Certificate(der: certificate.span)
        } catch {
            XCTFail("signed certificate parse failed: \(error)")
            return
        }

        XCTAssertNoThrow(try parsed.verifySignature())
        XCTAssertEqual(parsed.subjectPublicKeyInfo.algorithm, .ed25519)
    }

    func testRejectsModifiedEd25519CertificateSignature() throws {
        var certificate = makeSignedEd25519Certificate()
        certificate[certificate.count - 1] ^= 0x01
        let parsed: X509Certificate
        do {
            parsed = try X509Certificate(der: certificate.span)
        } catch {
            XCTFail("signed certificate parse failed: \(error)")
            return
        }

        do {
            try parsed.verifySignature()
            XCTFail("modified certificate signature was accepted")
        } catch {
            XCTAssertEqual(error, .signatureVerificationFailed)
        }
    }

    func testVerifiesP256ECDSACertificateSignature() throws {
        let certificate = makeECDSACertificate()
        let parsed = try X509Certificate(der: certificate.span)

        XCTAssertNoThrow(try parsed.verifySignature())
        XCTAssertEqual(parsed.signatureAlgorithm.objectIdentifier, [1, 2, 840, 10045, 4, 3, 2])
        XCTAssertEqual(parsed.subjectPublicKeyInfo.algorithm, .ecPublicKey(curve: .prime256v1))
    }

    func testRejectsModifiedP256ECDSACertificateSignature() throws {
        var certificate = makeECDSACertificate()
        certificate[certificate.count - 1] ^= 0x01
        let parsed = try X509Certificate(der: certificate.span)

        do {
            try parsed.verifySignature()
            XCTFail("modified P-256 ECDSA certificate signature was accepted")
        } catch {
            XCTAssertEqual(error, .signatureVerificationFailed)
        }
    }

    func testVerifiesP256ECDSASHA384AndSHA512Certificates() throws {
        let sha384 = bytes(
            "308201303081d7a003020102020107300a06082a8648ce3d04030330223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d" +
            "3235303130313030303030305a170d3335303130313030303030305a30223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013" +
            "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e" +
            "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f" +
            "9e162bce33576b315ececbb6406837bf51f5300a06082a8648ce3d04030303480030" +
            "450220230553b7ae39f4f20f6db904c015f1e3937a8fcf2dcf5782e2112bf1afaaaaff" +
            "022100b9e338d6dc2357d79fc7cf5efc96e93b42142d8aafe6976947e9e52d7c445037"
        )
        let sha512 = bytes(
            "308201303081d7a003020102020107300a06082a8648ce3d04030430223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d" +
            "3235303130313030303030305a170d3335303130313030303030305a30223120301e" +
            "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013" +
            "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e" +
            "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f" +
            "9e162bce33576b315ececbb6406837bf51f5300a06082a8648ce3d04030403480030" +
            "450221009f9486ec03f25bcfbd83f0bc716d43431e3c3113e86929332ce33e773d8722ae" +
            "02200e7a44c907d57549732d05e661f42218fcb041eec26726d09f09f9affe8ce098"
        )
        XCTAssertNoThrow(try X509Certificate(der: sha384.span).verifySignature())
        XCTAssertNoThrow(try X509Certificate(der: sha512.span).verifySignature())
    }

    func testParsesV3ExtensionsAndOwnsExtensionValue() throws {
        let certificate = makeCertificateWithExtensions()
        let parsed = try X509Certificate(der: certificate.span)

        XCTAssertEqual(parsed.extensions.count, 1)
        XCTAssertEqual(parsed.extensions[0].objectIdentifier, [2, 5, 29, 19])
        XCTAssertFalse(parsed.extensions[0].isCritical)
        let extensionValue = parsed.extensions[0].value
        XCTAssertEqual(copy(extensionValue.span), [])
    }

    func testRejectsDuplicateV3ExtensionObjectIdentifier() throws {
        let certificate = makeCertificateWithDuplicateExtensions()

        do {
            _ = try X509Certificate(der: certificate.span)
            XCTFail("duplicate extension was accepted")
        } catch let error {
            XCTAssertEqual(error, .extensions(.duplicateObjectIdentifier))
        }
    }

    func testMatchesDNSNameFromSubjectAlternativeNameOnly() throws {
        let parsed = try X509Certificate(der: makeCertificateWithSubjectAlternativeName().span)
        XCTAssertTrue(try parsed.matchesDNSName(ContiguousArray("A.COM".utf8).span))
        XCTAssertFalse(try parsed.matchesDNSName(ContiguousArray("b.a.com".utf8).span))

        do {
            _ = try parsed.matchesDNSName(ContiguousArray("bad name".utf8).span)
            XCTFail("invalid hostname syntax was accepted")
        } catch {
            XCTAssertEqual(error, .invalidHostname)
        }
    }

    private func makeCertificate() -> ContiguousArray<UInt8> {
        var tbs: ContiguousArray<UInt8> = [
            0x30, 0x5A,
            0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x30, 0x00,
            0x30, 0x1E,
            0x17, 0x0D
        ]
        tbs.append(contentsOf: ContiguousArray("240101000000Z".utf8))
        tbs.append(contentsOf: [0x17, 0x0D])
        tbs.append(contentsOf: ContiguousArray("250101000000Z".utf8))
        tbs.append(contentsOf: [
            0x30, 0x00,
            0x30, 0x2A,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x03, 0x21, 0x00
        ])
        tbs.append(contentsOf: repeatElement(0xA5, count: 32))

        var result: ContiguousArray<UInt8> = [0x30, 0x68]
        result.append(contentsOf: tbs)
        result.append(contentsOf: [
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x03, 0x00, 0x01, 0x02
        ])
        return result
    }

    private func makeCertificateWithExtensions() -> ContiguousArray<UInt8> {
        var result = makeCertificate()
        let extensions: [UInt8] = [
            0xA3, 0x0B,
            0x30, 0x09,
            0x30, 0x07,
            0x06, 0x03, 0x55, 0x1D, 0x13,
            0x04, 0x00
        ]
        result.insert(contentsOf: extensions, at: 2 + 2 + 0x5A)
        result[1] += UInt8(extensions.count)
        result[3] += UInt8(extensions.count)
        return result
    }

    private func makeCertificateWithDuplicateExtensions() -> ContiguousArray<UInt8> {
        var result = makeCertificate()
        let extensions: [UInt8] = [
            0xA3, 0x14,
            0x30, 0x12,
            0x30, 0x07, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x00,
            0x30, 0x07, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x00
        ]
        result.insert(contentsOf: extensions, at: 2 + 2 + 0x5A)
        result[1] += UInt8(extensions.count)
        result[3] += UInt8(extensions.count)
        return result
    }

    private func makeCertificateWithSubjectAlternativeName() -> ContiguousArray<UInt8> {
        var result = makeCertificate()
        let extensionBytes: [UInt8] = [
            0xA3, 0x14,
            0x30, 0x12,
            0x30, 0x10,
            0x06, 0x03, 0x55, 0x1D, 0x11,
            0x04, 0x09,
            0x30, 0x07, 0x82, 0x05, 0x61, 0x2E, 0x63, 0x6F, 0x6D
        ]
        result.insert(contentsOf: extensionBytes, at: 94)
        result[1] += UInt8(extensionBytes.count)
        result[3] += UInt8(extensionBytes.count)
        return result
    }

    private func makeSignedEd25519Certificate() -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(169)
        result.append(contentsOf: bytes(
            "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a" +
            "170d3235303130313030303030305a3000302a300506032b6570032100" +
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
            "300506032b6570034100" +
            "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b" +
            "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
        ))
        return result
    }

    private func makeECDSACertificate() -> ContiguousArray<UInt8> {
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

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    private func find(_ needle: [UInt8], in haystack: ContiguousArray<UInt8>) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        var start = 0
        while start <= haystack.count - needle.count {
            var matches = true
            var index = 0
            while index < needle.count {
                if haystack[start + index] != needle[index] {
                    matches = false
                    break
                }
                index += 1
            }
            if matches { return start }
            start += 1
        }
        return nil
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
