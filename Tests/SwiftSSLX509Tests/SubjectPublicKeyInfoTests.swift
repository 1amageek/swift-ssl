import XCTest
import SwiftSSLCore
import SwiftSSLX509

final class SubjectPublicKeyInfoTests: XCTestCase {
    func testParsesX25519SubjectPublicKeyInfoWithoutCopyingKeyBytes() throws {
        var der: ContiguousArray<UInt8> = [
            0x30, 0x2A,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x03, 0x21, 0x00
        ]
        der.append(contentsOf: repeatElement(0xA5, count: 32))
        let info = try SubjectPublicKeyInfo(der: der.span)
        XCTAssertEqual(info.algorithm, .x25519)
        XCTAssertEqual(info.publicKeyByteCount, 32)
        try info.withPublicKeyBytes { key in
            XCTAssertEqual(copy(key), Array(repeating: 0xA5, count: 32))
        }
    }

    func testRejectsNonZeroUnusedBits() throws {
        let der: ContiguousArray<UInt8> = [
            0x30, 0x0C,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x03, 0x03, 0x01, 0x80, 0x00
        ]
        XCTAssertThrowsError(try SubjectPublicKeyInfo(der: der.span)) { error in
            XCTAssertEqual(error as? SubjectPublicKeyInfoError, .invalidKeyBitString)
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
