import Foundation
import XCTest

@testable import SSLCrypto

final class AESKeyWrapTests: XCTestCase {
  func testRFC3394KnownAnswerVectors() throws {
    let vectors = [
      (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
      ),
      (
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"
      ),
      (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"
      ),
    ]

    for (keyHex, plaintextHex, expectedHex) in vectors {
      let key = bytes(keyHex)
      let plaintext = bytes(plaintextHex)
      var wrapped = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count + 8)
      try wrapped.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try AESKeyWrap.wrap(key: key.span, plaintext: plaintext.span, into: &output)
      }
      XCTAssertEqual(hex(wrapped), expectedHex)

      var recovered = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count)
      try recovered.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try AESKeyWrap.unwrap(key: key.span, wrapped: wrapped.span, into: &output)
      }
      XCTAssertEqual(recovered, plaintext)
    }
  }

  func testIntegrityFailureDoesNotSilentlyReturnPlaintext() throws {
    let key = bytes("000102030405060708090a0b0c0d0e0f")
    let wrapped = bytes("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
    var mutated = wrapped
    mutated[0] ^= 1
    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: 16)
    XCTAssertThrowsError(
      try recovered.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try AESKeyWrap.unwrap(key: key.span, wrapped: mutated.span, into: &output)
      }
    )
    XCTAssertEqual(recovered, ContiguousArray(repeating: 0xA5, count: 16))
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }

  private func hex(_ value: ContiguousArray<UInt8>) -> String {
    value.map { String(format: "%02x", $0) }.joined()
  }
}
