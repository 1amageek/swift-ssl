import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class HMACSHA2Tests: XCTestCase {
    func testRFC4231CaseOneSHA384AndSHA512() throws {
        let key = ContiguousArray<UInt8>(repeating: 0x0B, count: 20)
        let message = ContiguousArray("Hi There".utf8)
        let expected384 = bytes("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
        let expected512 = bytes("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")

        var actual384 = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA384.tagByteCount)
        var span384 = actual384.mutableSpan
        try HMACSHA384.authenticate(message.span, using: key.span, into: &span384)
        XCTAssertEqual(actual384, expected384)

        var actual512 = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA512.tagByteCount)
        var span512 = actual512.mutableSpan
        try HMACSHA512.authenticate(message.span, using: key.span, into: &span512)
        XCTAssertEqual(actual512, expected512)
    }

    func testContextVerificationRejectsModifiedCode() throws {
        let key = ContiguousArray("key".utf8)
        let message = ContiguousArray("message".utf8)
        var code = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA384.tagByteCount)
        var codeSpan = code.mutableSpan
        try HMACSHA384.authenticate(message.span, using: key.span, into: &codeSpan)
        var context = try HMACSHA384.makeContext(authenticatingWith: key.span)
        try context.update(message.span)
        let valid = try context.isValidAuthenticationCode(code.span)
        XCTAssertTrue(valid)
        code[0] ^= 1
        var secondContext = try HMACSHA384.makeContext(authenticatingWith: key.span)
        try secondContext.update(message.span)
        let invalid = try secondContext.isValidAuthenticationCode(code.span)
        XCTAssertFalse(invalid)
    }

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<next], radix: 16)!)
            index = next
        }
        return result
    }
}
