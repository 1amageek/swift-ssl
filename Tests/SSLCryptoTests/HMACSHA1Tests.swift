import SSLCore
import XCTest

@testable import SSLCrypto

final class HMACSHA1Tests: XCTestCase {
  func testRFC2202KnownAnswerVectors() throws {
    let vectors: [(ContiguousArray<UInt8>, ContiguousArray<UInt8>, String)] = [
      (
        ContiguousArray(repeating: 0x0B, count: 20),
        ContiguousArray("Hi There".utf8),
        "b617318655057264e28bc0b6fb378c8ef146be00"
      ),
      (
        ContiguousArray("Jefe".utf8),
        ContiguousArray("what do ya want for nothing?".utf8),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
      ),
      (
        ContiguousArray(repeating: 0xAA, count: 80),
        ContiguousArray("Test Using Larger Than Block-Size Key - Hash Key First".utf8),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
      ),
    ]

    for (key, message, expected) in vectors {
      XCTAssertEqual(try authenticationCode(key: key, message: message), expected)
    }
  }

  func testIncrementalAndValidationContracts() throws {
    let key = ContiguousArray("key".utf8)
    let first = ContiguousArray("first".utf8)
    let second = ContiguousArray("second".utf8)
    var message = first
    message.append(contentsOf: second)

    var expected = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA1.tagByteCount
    )
    do {
      var output = expected.mutableSpan
      try HMACSHA1.authenticate(message.span, using: key.span, into: &output)
    }

    var context = try HMACSHA1.makeContext(authenticatingWith: key.span)
    try context.update(first.span)
    try context.update(second.span)
    var actual = ContiguousArray<UInt8>(
      repeating: 0,
      count: HMACSHA1.tagByteCount
    )
    do {
      var output = actual.mutableSpan
      try context.finalize(into: &output)
    }
    XCTAssertEqual(actual, expected)
    XCTAssertTrue(
      try HMACSHA1.isValidAuthenticationCode(
        expected.span,
        authenticating: message.span,
        using: key.span
      )
    )
    let truncated = ContiguousArray(expected.dropLast())
    XCTAssertFalse(
      try HMACSHA1.isValidAuthenticationCode(
        truncated.span,
        authenticating: message.span,
        using: key.span
      )
    )
  }

  private func authenticationCode(
    key: ContiguousArray<UInt8>,
    message: ContiguousArray<UInt8>
  ) throws -> String {
    var output = ContiguousArray<UInt8>(repeating: 0, count: HMACSHA1.tagByteCount)
    do {
      var destination = output.mutableSpan
      try HMACSHA1.authenticate(message.span, using: key.span, into: &destination)
    }
    let digits = ContiguousArray("0123456789abcdef".utf8)
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(output.count * 2)
    for byte in output {
      encoded.append(digits[Int(byte >> 4)])
      encoded.append(digits[Int(byte & 0x0F)])
    }
    return String(decoding: encoded, as: UTF8.self)
  }
}
