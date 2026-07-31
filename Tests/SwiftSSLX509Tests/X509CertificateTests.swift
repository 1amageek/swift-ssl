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
        var tbsByteCount = 0
        try parsed.withTBSCertificateBytes { tbs in
            tbsByteCount = tbs.count
        }
        XCTAssertEqual(tbsByteCount, 92)
        try parsed.withSignatureBytes { signature in
            XCTAssertEqual(copy(signature), [1, 2])
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
