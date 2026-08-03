import XCTest
import SSLCore
import SSLX509

final class PrivateKeyInfoTests: XCTestCase {
    func testParsesX25519PrivateKeyInfo() throws {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2C,
            0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x04, 0x20
        ]
        der.append(contentsOf: repeatElement(0x5A, count: 32))
        let info = try PrivateKeyInfo(der: der.span)
        XCTAssertEqual(info.version, 0)
        XCTAssertEqual(info.algorithm, .x25519)
        XCTAssertEqual(info.privateKeyByteCount, 32)
        try info.withPrivateKeyBytes { key in
            XCTAssertEqual(copy(key), Array(repeating: 0x5A, count: 32))
        }
    }

    func testVersionOneRequiresPublicKeyField() throws {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2C,
            0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x04, 0x20
        ]
        der.append(contentsOf: repeatElement(0x5A, count: 32))
        do {
            let info = try PrivateKeyInfo(der: der.span)
            _ = consume info
            XCTFail("version-one PrivateKeyInfo without a public key was accepted")
        } catch {
            XCTAssertEqual(error as? PrivateKeyInfoError, .invalidVersion(1))
        }
    }

    func testParsesP256PKCS8AndRFC5915ECPrivateKey() throws {
        let scalar = Array(repeating: UInt8(0), count: 31) + [1]
        let publicPoint = bytes(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )
        var ec: ContiguousArray<UInt8> = [
            0x30, 0x75,
            0x02, 0x01, 0x01,
            0x04, 0x20
        ]
        ec.append(contentsOf: scalar)
        ec.append(contentsOf: [
            0xA0, 0x0A,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x81, 0x42, 0x00
        ])
        ec.append(contentsOf: publicPoint)

        var der: ContiguousArray<UInt8> = [
            0x30, 0x81, 0x91,
            0x02, 0x01, 0x00,
            0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x04, 0x77
        ]
        der.append(contentsOf: ec)

        let info = try PrivateKeyInfo(der: der.span)
        let key = try info.ecPrivateKey()
        XCTAssertEqual(key.version, 1)
        XCTAssertEqual(key.curve, .prime256v1)
        XCTAssertEqual(key.privateKeyByteCount, 32)
        try key.withPrivateKeyBytes { bytes in
            XCTAssertEqual(copy(bytes), scalar)
        }
        guard let encodedPublicKey = key.publicKey else {
            return XCTFail("RFC 5915 public key field was not retained")
        }
        XCTAssertEqual(copy(encodedPublicKey.span), publicPoint)
    }

    func testRejectsMismatchedRFC5915Curve() throws {
        var ec: ContiguousArray<UInt8> = [
            0x30, 0x31,
            0x02, 0x01, 0x01,
            0x04, 0x20
        ]
        ec.append(contentsOf: repeatElement(0x01, count: 32))
        ec.append(contentsOf: [
            0xA0, 0x0A,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
        ])
        do {
            let key = try ECPrivateKey(der: ec.span, expectedCurve: .secp384r1)
            _ = consume key
            XCTFail("mismatched curve was accepted")
        } catch {
            XCTAssertEqual(error as? ECPrivateKeyError, .invalidParameters)
        }
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

    private func bytes(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            result.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return result
    }
}
