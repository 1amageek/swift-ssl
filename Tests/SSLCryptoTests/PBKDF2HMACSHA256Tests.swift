import XCTest
import SSLCore
import SSLCrypto

final class PBKDF2HMACSHA256Tests: XCTestCase {
  func testKnownAnswers() throws {
    let password = ContiguousArray("password".utf8)
    let salt = ContiguousArray("salt".utf8)
    let cases: [(UInt32, String)] = [
      (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
      (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
      (4_096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
    ]

    for (iterations, expectedHex) in cases {
      var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
      var destination = output.mutableSpan
      try PBKDF2HMACSHA256.deriveKey(
        password: password.span,
        salt: salt.span,
        iterations: iterations,
        into: &destination
      )
      XCTAssertEqual(output, bytes(expectedHex))
    }
  }

  func testDerivesMultipleBlocks() throws {
    let password = ContiguousArray("password".utf8)
    let salt = ContiguousArray("salt".utf8)
    var output = ContiguousArray<UInt8>(repeating: 0, count: 40)
    var destination = output.mutableSpan
    try PBKDF2HMACSHA256.deriveKey(
      password: password.span,
      salt: salt.span,
      iterations: 2,
      into: &destination
    )

    XCTAssertEqual(
      output,
      bytes(
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" +
          "830651afcb5c862f"
      )
    )
  }

  func testValidationFailsBeforeOutputMutation() throws {
    let password: ContiguousArray<UInt8> = [1, 2, 3]
    let salt: ContiguousArray<UInt8> = [4, 5, 6]
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
    var destination = output.mutableSpan

    XCTAssertThrowsError(
      try PBKDF2HMACSHA256.deriveKey(
        password: password.span,
        salt: salt.span,
        iterations: 0,
        into: &destination
      )
    ) { error in
      XCTAssertEqual(error as? PBKDF2Error, .invalidIterationCount(0))
    }
    XCTAssertEqual(output, ContiguousArray(repeating: 0xA5, count: 32))
  }

  private func bytes(_ hex: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      result.append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
    return result
  }
}
