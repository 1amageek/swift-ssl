import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class HMACDRBGTests: XCTestCase {
  func testSP80090AStyleDeterministicGeneration() throws {
    let entropy = FixedEntropy(bytes: ContiguousArray(0..<32))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    var generator = try HMACDRBG(
      entropy: entropy,
      nonce: nonce.span,
      personalization: personalization.span
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 80)
    var outputSpan = output.mutableSpan
    try generator.generate(into: &outputSpan)

    XCTAssertEqual(
      output,
      bytes(
        "acb4c0527346343f45266a99a5ea86e9493b69635f509ed6871d4c871f93613b70af78045a86189e93f2adcbd7f4533c1bf27f60b443c1f0514ffaaf3102514a61b41b7d8c9916021978e3f64118ca08"
      )
    )
  }

  func testAdditionalInputMatchesIndependentVector() throws {
    let entropy = FixedEntropy(bytes: ContiguousArray(0..<32))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    let additional = ContiguousArray<UInt8>(64..<72)
    var generator = try HMACDRBG(
      entropy: entropy,
      nonce: nonce.span,
      personalization: personalization.span
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 64)
    var outputSpan = output.mutableSpan
    try generator.generate(additionalInput: additional.span, into: &outputSpan)

    XCTAssertEqual(
      output,
      bytes(
        "105183504d7ca550b85a69a1039b9533c4b26b7d62910c804988e067bab5c48c76c5acce2cf90ebe7b14ed0bf1e493c7c5d5ac1614dc8c3d9f1b9f48f3e4bf8c"
      )
    )
  }

  func testOutputLimitFailsBeforeMutation() throws {
    let entropy = FixedEntropy(bytes: ContiguousArray(0..<32))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    var generator = try HMACDRBG(
      entropy: entropy,
      nonce: nonce.span,
      personalization: personalization.span
    )
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5, count: HMACDRBG.maximumRequestByteCount + 1)
    let original = output
    do {
      var outputSpan = output.mutableSpan
      try generator.generate(into: &outputSpan)
      XCTFail("oversized request was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .outputTooLarge(
          limit: HMACDRBG.maximumRequestByteCount, actual: HMACDRBG.maximumRequestByteCount + 1)
      )
    }
    XCTAssertEqual(output, original)
  }

  func testEntropyFailureIsPropagated() {
    let entropy = FixedEntropy(bytes: ContiguousArray(repeating: 0, count: 31))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    do {
      let unused = try HMACDRBG(
        entropy: entropy,
        nonce: nonce.span,
        personalization: personalization.span
      )
      _ = unused
      XCTFail("short entropy was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .entropy(.partialFill(expected: HMACDRBG.entropyByteCount, actual: 31))
      )
    }
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

private struct FixedEntropy: EntropySource {
  let bytes: ContiguousArray<UInt8>

  func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
    guard destination.count == bytes.count else {
      throw .partialFill(expected: destination.count, actual: bytes.count)
    }
    var index = 0
    while index < bytes.count {
      destination[index] = bytes[index]
      index += 1
    }
  }
}
