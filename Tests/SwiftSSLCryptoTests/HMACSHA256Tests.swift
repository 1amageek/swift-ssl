import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class HMACSHA256Tests: XCTestCase {
  func testRFC4231KnownAnswerVectors() throws {
    let vectors:
      [(
        key: ContiguousArray<UInt8>,
        message: ContiguousArray<UInt8>,
        authenticationCode: String
      )] = [
        (
          ContiguousArray(repeating: 0x0B, count: 20),
          ContiguousArray("Hi There".utf8),
          "b0344c61d8db38535ca8afceaf0bf12b"
            + "881dc200c9833da726e9376c2e32cff7"
        ),
        (
          ContiguousArray("Jefe".utf8),
          ContiguousArray("what do ya want for nothing?".utf8),
          "5bdcc146bf60754e6a042426089575c7"
            + "5a003f089d2739839dec58b964ec3843"
        ),
        (
          ContiguousArray(repeating: 0xAA, count: 20),
          ContiguousArray(repeating: 0xDD, count: 50),
          "773ea91e36800e46854db8ebd09181a7"
            + "2959098b3ef8c122d9635514ced565fe"
        ),
        (
          ContiguousArray(1...25),
          ContiguousArray(repeating: 0xCD, count: 50),
          "82558a389a443c0ea4cc819899f2083a"
            + "85f0faa3e578f8077a2e3ff46729665b"
        ),
        (
          ContiguousArray(repeating: 0xAA, count: 131),
          ContiguousArray(
            "Test Using Larger Than Block-Size Key - Hash Key First".utf8
          ),
          "60e431591ee0b67f0d8a26aacbf5b77f"
            + "8e0bc6213728c5140546040f0ee37f54"
        ),
        (
          ContiguousArray(repeating: 0xAA, count: 131),
          ContiguousArray(
            """
            This is a test using a larger than block-size key and a larger \
            than block-size data. The key needs to be hashed before being \
            used by the HMAC algorithm.
            """.utf8
          ),
          "9b09ffa71b942fcb27635fbcd5b0e944"
            + "bfdc63644f0713938a7f51535c3a35e2"
        ),
      ]

    for vector in vectors {
      XCTAssertEqual(
        try authenticationCodeHex(
          key: vector.key,
          message: vector.message
        ),
        vector.authenticationCode
      )
    }
  }

  func testIncrementalUpdatesMatchOneShotAuthentication() throws {
    let key = ContiguousArray<UInt8>(repeating: 0xA5, count: 80)
    let first = ContiguousArray("first segment".utf8)
    let second = ContiguousArray<UInt8>(repeating: 0x5A, count: 113)
    let third = ContiguousArray("third segment".utf8)
    var message = first
    message.append(contentsOf: second)
    message.append(contentsOf: third)

    let expected = try authenticationCode(key: key, message: message)
    var context = try HMACSHA256.makeContext(
      authenticatingWith: key.span
    )
    try context.update(first.span)
    try context.update(second.span)
    try context.update(third.span)

    var actual = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA256.tagByteCount
    )
    do {
      var output = actual.mutableSpan
      try context.finalize(into: &output)
    }

    XCTAssertEqual(actual, expected)
  }

  func testAuthenticationCodeValidation() throws {
    let key = ContiguousArray("validation key".utf8)
    let message = ContiguousArray("authenticated message".utf8)
    let authenticationCode = try authenticationCode(
      key: key,
      message: message
    )

    XCTAssertTrue(
      try HMACSHA256.isValidAuthenticationCode(
        authenticationCode.span,
        authenticating: message.span,
        using: key.span
      )
    )

    var incorrectCode = authenticationCode
    incorrectCode[incorrectCode.startIndex] ^= 0x01
    XCTAssertFalse(
      try HMACSHA256.isValidAuthenticationCode(
        incorrectCode.span,
        authenticating: message.span,
        using: key.span
      )
    )

    let truncatedCode = ContiguousArray(authenticationCode.dropLast())
    XCTAssertFalse(
      try HMACSHA256.isValidAuthenticationCode(
        truncatedCode.span,
        authenticating: message.span,
        using: key.span
      )
    )
  }

  func testIncrementalRejectsNonExactOutputWithoutModification() throws {
    let key = ContiguousArray("key".utf8)
    let message = ContiguousArray("message".utf8)
    for outputByteCount in [
      HMACSHA256.tagByteCount - 1,
      HMACSHA256.tagByteCount + 1,
    ] {
      var context = try HMACSHA256.makeContext(
        authenticatingWith: key.span
      )
      try context.update(message.span)
      var output = ContiguousArray<UInt8>(
        repeating: 0xA5,
        count: outputByteCount
      )

      do {
        var outputSpan = output.mutableSpan
        try context.finalize(into: &outputSpan)
        XCTFail("HMAC-SHA-256 finalized into a non-exact output")
      } catch {
        XCTAssertEqual(
          error,
          .invalidOutputLength(
            expected: HMACSHA256.tagByteCount,
            actual: outputByteCount
          )
        )
      }

      XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
    }
  }

  func testOneShotRejectsNonExactOutputWithoutModification() {
    let key = ContiguousArray("key".utf8)
    let message = ContiguousArray("message".utf8)

    for outputByteCount in [
      HMACSHA256.tagByteCount - 1,
      HMACSHA256.tagByteCount + 1,
    ] {
      var output = ContiguousArray<UInt8>(
        repeating: 0xA5,
        count: outputByteCount
      )

      do {
        var outputSpan = output.mutableSpan
        try HMACSHA256.authenticate(
          message.span,
          using: key.span,
          into: &outputSpan
        )
        XCTFail("HMAC-SHA-256 authenticated into a non-exact output")
      } catch {
        XCTAssertEqual(
          error,
          .invalidOutputLength(
            expected: HMACSHA256.tagByteCount,
            actual: outputByteCount
          )
        )
      }

      XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
    }
  }

  private func authenticationCodeHex(
    key: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>
  ) throws -> String {
    try hexString(authenticationCode(key: key, message: message))
  }

  private func authenticationCode(
    key: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>
  ) throws -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA256.tagByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try HMACSHA256.authenticate(
        message.span,
        using: key.span,
        into: &outputSpan
      )
    }
    return output
  }

  private func hexString(
    _ bytes: ContiguousArray<UInt8>
  ) -> String {
    let digits = ContiguousArray("0123456789abcdef".utf8)
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(bytes.count * 2)
    for byte in bytes {
      encoded.append(digits[Int(byte >> 4)])
      encoded.append(digits[Int(byte & 0x0F)])
    }
    return String(decoding: encoded, as: UTF8.self)
  }
}
