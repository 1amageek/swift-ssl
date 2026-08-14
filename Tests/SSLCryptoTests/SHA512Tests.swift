import SSLCore
import XCTest

@testable import SSLCrypto

final class SHA512Tests: XCTestCase {
  func testSHA512ABC() throws {
    let expected = bytes(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: SHA512.digestByteCount)
    var span = output.mutableSpan
    try SHA512.hash(ContiguousArray("abc".utf8).span, into: &span)
    XCTAssertEqual(output, expected)
  }

  func testSHA384ABCIncrementalAndClone() throws {
    let expected = bytes(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    )
    let input = ContiguousArray("abc".utf8)
    var context = SHA384Context()
    try context.update(input.span.extracting(0..<1))
    let clone = context.clone()
    try context.update(input.span.extracting(1..<input.count))
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: SHA384.digestByteCount)
    var outputSpan = output.mutableSpan
    try context.finalize(into: &outputSpan)
    XCTAssertEqual(output, expected)

    var cloneContext = clone
    try cloneContext.update(ContiguousArray("bc".utf8).span)
    var cloneOutput = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
    var cloneSpan = cloneOutput.mutableSpan
    try cloneContext.finalize(into: &cloneSpan)
    XCTAssertEqual(cloneOutput, expected)
  }

  func testRejectsWrongOutputLengthWithoutMutation() throws {
    let original = ContiguousArray<UInt8>(repeating: 0xA5, count: SHA512.digestByteCount - 1)
    var output = original
    let context = SHA512Context()
    var wrongSpan = output.mutableSpan
    do {
      try context.finalize(into: &wrongSpan)
      XCTFail("SHA-512 accepted an incorrectly sized output")
    } catch {
      XCTAssertEqual(error, .invalidOutputLength(expected: 64, actual: 63))
    }
    XCTAssertEqual(output, original)
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
