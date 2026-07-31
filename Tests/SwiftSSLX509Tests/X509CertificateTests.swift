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

    func testVerifiesP384ECDSACertificateSignature() throws {
        let certificate = try X509Certificate(der: makeP384ECDSACertificate().span)
        XCTAssertNoThrow(try certificate.verifySignature())
        XCTAssertEqual(certificate.subjectPublicKeyInfo.algorithm, .ecPublicKey(curve: .secp384r1))
    }

    func testVerifiesP521ECDSACertificateSignature() throws {
        let certificate = try X509Certificate(der: makeP521ECDSACertificate().span)
        XCTAssertNoThrow(try certificate.verifySignature())
        XCTAssertEqual(certificate.subjectPublicKeyInfo.algorithm, .ecPublicKey(curve: .secp521r1))
    }

    func testVerifiesRSAPSSCertificateSignature() throws {
        let certificate = try X509Certificate(der: makeRSAPSSCertificate().span)
        XCTAssertNoThrow(try certificate.verifySignature())
        XCTAssertEqual(certificate.subjectPublicKeyInfo.algorithm, .rsaEncryption)
    }

    func testValidatesP256LeafAgainstTrustAnchorAndSAN() throws {
        let root = try X509Certificate(der: makePathRootCertificate().span)
        let leaf = try X509Certificate(der: makePathLeafCertificate().span)
        let validator = try X509PathValidator(trustAnchors: ContiguousArray([root]))

        XCTAssertNoThrow(try validator.validate(
            leaf: leaf,
            at: try VerificationInstant(secondsSinceUnixEpoch: 1_735_689_600, nanoseconds: 0),
            hostname: ContiguousArray("swift-ssl-leaf.example".utf8).span
        ))
    }

    func testPathValidatorRejectsModifiedLeafSignature() throws {
        let root = try X509Certificate(der: makePathRootCertificate().span)
        var leafDER = makePathLeafCertificate()
        leafDER[leafDER.count - 1] ^= 0x01
        let leaf = try X509Certificate(der: leafDER.span)
        let validator = try X509PathValidator(trustAnchors: ContiguousArray([root]))

        do {
            try validator.validate(
                leaf: leaf,
                at: try VerificationInstant(secondsSinceUnixEpoch: 1_735_689_600, nanoseconds: 0)
            )
            XCTFail("modified leaf signature was accepted")
        } catch let error as X509PathError {
            guard case .signature(.signatureVerificationFailed) = error else {
                XCTFail("unexpected path validation error: \(error)")
                return
            }
        }
    }

    func testPathValidatorRejectsIssuerWithoutCAConstraint() throws {
        var rootDER = makePathRootCertificate()
        let nestedBasicConstraints: [UInt8] = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x02]
        guard let booleanOffset = find(nestedBasicConstraints, in: rootDER) else {
            XCTFail("root BasicConstraints fixture was not found")
            return
        }
        rootDER[booleanOffset + 4] = 0
        let root = try X509Certificate(der: rootDER.span)
        let leaf = try X509Certificate(der: makePathLeafCertificate().span)
        let validator = try X509PathValidator(trustAnchors: ContiguousArray([root]))

        do {
            try validator.validate(
                leaf: leaf,
                at: try VerificationInstant(secondsSinceUnixEpoch: 1_735_689_600, nanoseconds: 0)
            )
            XCTFail("non-CA issuer was accepted")
        } catch let error as X509PathError {
            XCTAssertEqual(error, .issuerNotCA)
        }
    }

    func testPathValidatorRejectsHostnameMismatch() throws {
        let root = try X509Certificate(der: makePathRootCertificate().span)
        let leaf = try X509Certificate(der: makePathLeafCertificate().span)
        let validator = try X509PathValidator(trustAnchors: ContiguousArray([root]))

        do {
            try validator.validate(
                leaf: leaf,
                at: try VerificationInstant(secondsSinceUnixEpoch: 1_735_689_600, nanoseconds: 0),
                hostname: ContiguousArray("wrong.example".utf8).span
            )
            XCTFail("hostname mismatch was accepted")
        } catch let error as X509PathError {
            guard case .identity(.noMatchingSubjectAlternativeName) = error else {
                XCTFail("unexpected path error: \(error)")
                return
            }
        }
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

    private func makeP384ECDSACertificate() -> ContiguousArray<UInt8> {
        bytes(
            "308201833082010aa003020102020101300a06082a8648ce3d0403033021311f301d06035504030c1673776966742d73736c2d703338342e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a3021311f301d06035504030c1673776966742d73736c2d703338342e6578616d706c653076301006072a8648ce3d020106052b8104002203620004aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fa316301430120603551d130101ff040830060101ff020101300a06082a8648ce3d040303036700306402302c8f2d979504b245044527bfeebf34bf0feb065599f5ec0243572bf6481d03487106199aa6ddf1f000b77d6f2718e0a302302efccfa841e832e46c38ec9a2f0268a7274421f49b4db42ceee560ad53d689ad24bb41d443964c77492b2f874012763c"
        )
    }

    private func makeP521ECDSACertificate() -> ContiguousArray<UInt8> {
        bytes(
            "308201ce30820130a003020102020101300a06082a8648ce3d0403043021311f301d06035504030c1673776966742d73736c2d703532312e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a3021311f301d06035504030c1673776966742d73736c2d703532312e6578616d706c6530819b301006072a8648ce3d020106052b81040023038186000400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650a316301430120603551d130101ff040830060101ff020101300a06082a8648ce3d04030403818b00308187024200a71f81d5d29a1241748dc7717dcd56ee91e0869eb6f0e69eefd14ee9cda2f558f3841871e5fba2c035472632c8d5f3f42e02357822b8f85f5d9d5630264b465ccb02412bf9dcec5c8c46299209130519814a6a23def11dc84f5cca92c6eb641a5f47d28d940d1f90aa1d37c0ca934aec75066346b4060b19688e35e476329bdfca289ea0"
        )
    }

    private func makeRSAPSSCertificate() -> ContiguousArray<UInt8> {
        bytes(
            "3082033f308201f3a003020102020101304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012030233121301f06035504030c1873776966742d73736c2d7273617073732e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a30233121301f06035504030c1873776966742d73736c2d7273617073732e6578616d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100bc1bcb3fdaedf793a9094cf688e4e7e0a8ce0f6853882e76e0d7349ccf8f4eca32eeb34e37ce7b10a85fcafae18571921e6182425ca5a77191d71c0813b9dd14629616d9d7c3e5d0ac9078fa9b377965556ed81a80078e568580ff55624eb8c6bda7eb3e9320e193cedb1066870871f7ec63b20eb039d17c702471d5ede77e791cf55d9b17cd20ecc62c912314431add1aa31c559abe0373b912f4216cff2aeecfb37f1e1be7b4b5c6f9c2f14aa5da11d14cffb8076f40ac25fc77148ecfd420bfd162299169bcc27ddf8632cca03a88d1d52ceb43206769b263a67619742d002237be09b3f93946d8398e097ef23be851478a36db4d6cf428e4f5997db265110203010001a316301430120603551d130101ff040830060101ff020101304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820101004db3a8828ddd7a4cb39682bb50ea29d5bf01beeb4a43fa29bc71259d1fbe7c0359186982687128e8a3b6da77dc35d386efbd6b7a752ac0ce0f0c9d4ef18e31400d52e6bf694f2202ca6eb66647cd41bb0acedfad5e5ff095ac67fa327dfbe00cc918cc3e4b8b4c405a3f7104a41ad3b76966042177a3b9d8c19dcdd498c7b5a8761aaf8d55fd2b935f020e490dc41b1ef3b2635e085cf980057ffc06068643fa90fd47cb79cc43c79e610b1d2222943862abde66faaf2532b75dab38419b97a3bcd3d36efa91f1e10c11f414d3db8a4c13d21b202dd596cbf7839c584a03b3a5dbd827ea8b16ddfeec0dd53a2a531e96152059eaf245766845437ce9b8908696"
        )
    }

    private func makePathRootCertificate() -> ContiguousArray<UInt8> {
        bytes(
            "308201363081dda003020102020101300a06082a8648ce3d040302301931173015" +
            "06035504030c0e73776966742d73736c2d726f6f74301e170d323530313031303030" +
            "3030305a170d3335303130313030303030305a30193117301506035504030c0e7377" +
            "6966742d73736c2d726f6f743059301306072a8648ce3d020106082a8648ce3d030107" +
            "034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c" +
            "2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5a3" +
            "16301430120603551d130101ff040830060101ff020102300a06082a8648ce3d040302" +
            "034800304502204e426efc04664694b4d14b24ff041320c4f08c4676966203db940db70" +
            "ac42ef3022100e2cee6a4742c6dca4bb5e84e95f0ad4c7af2d2920c7a2021a2419d1750" +
            "ebd51b"
        )
    }

    private func makePathLeafCertificate() -> ContiguousArray<UInt8> {
        bytes(
            "3082015d30820102a003020102020102300a06082a8648ce3d040302301931173015" +
            "06035504030c0e73776966742d73736c2d726f6f74301e170d323530313031303030" +
            "3030305a170d3335303130313030303030305a3021311f301d06035504030c167377" +
            "6966742d73736c2d6c6561662e6578616d706c653059301306072a8648ce3d02010608" +
            "2a8648ce3d030107034200047cf27b188d034f7e8a52380304b51ac3c08969e277f21b" +
            "35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04" +
            "b79d227873d1a3333031300c0603551d130101ff0402300030210603551d11041a3018" +
            "821673776966742d73736c2d6c6561662e6578616d706c65300a06082a8648ce3d040302" +
            "0349003046022100b50cf4bb68570659313890767901e1e7fa6d6b5dc82967a520e66c42" +
            "ee22f80b022100c2b20993ca673a271ec34fc291a1d27e208640a9d84395833e27d40d7e" +
            "a2cc76"
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
