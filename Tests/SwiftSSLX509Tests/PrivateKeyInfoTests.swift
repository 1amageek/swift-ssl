import XCTest
import SwiftSSLCore
import SwiftSSLX509

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
        XCTAssertThrowsError(try PrivateKeyInfo(der: der.span)) { error in
            XCTAssertEqual(error as? PrivateKeyInfoError, .invalidVersion(1))
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
}
