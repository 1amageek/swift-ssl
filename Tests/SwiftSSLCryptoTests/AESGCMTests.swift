import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class AESGCMTests: XCTestCase {
  func testAESBlockKnownAnswerVectorsForAllKeySizes() throws {
    let plaintext = bytes("00112233445566778899aabbccddeeff")
    let vectors = [
      ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
      ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
      (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089"
      ),
    ]

    for (keyHex, expectedHex) in vectors {
      let key = bytes(keyHex)
      var output = ContiguousArray<UInt8>(repeating: 0, count: 16)
      let blockCipher = AESBlockCipher(key: key.span)
      output.withUnsafeMutableBufferPointer { buffer in
        var outputSpan = MutableSpan(_unsafeElements: buffer)
        blockCipher.encrypt(plaintext.span, into: &outputSpan)
      }
      XCTAssertEqual(hex(output), expectedHex)
    }
  }

  func testNISTAES128EmptyMessage() throws {
    let key = bytes("00000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    var output = ContiguousArray<UInt8>(repeating: 0, count: 16)
    var cipher = try AESGCM(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try output.withUnsafeMutableBufferPointer { buffer in
      var outputSpan = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: Span(_unsafeElements: empty),
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &outputSpan
      )
    }

    XCTAssertEqual(hex(output), "58e2fccefa7e3061367f1d57a4e7455a")
  }

  func testNISTAES128SingleBlockRoundTrip() throws {
    let key = bytes("00000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    let plaintext = bytes("00000000000000000000000000000000")
    let expected = "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var cipher = try AESGCM(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try sealed.withUnsafeMutableBufferPointer { buffer in
      var sealedSpan = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: plaintext.span,
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &sealedSpan
      )
    }
    XCTAssertEqual(hex(sealed), expected)

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: 16)
    try recovered.withUnsafeMutableBufferPointer { buffer in
      var recoveredSpan = MutableSpan(_unsafeElements: buffer)
      try cipher.open(
        ciphertextAndTag: sealed.span,
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &recoveredSpan
      )
    }
    XCTAssertEqual(recovered, plaintext)
  }

  func testNISTAdditionalAuthenticatedDataVector() throws {
    let key = bytes("feffe9928665731c6d6a8f9467308308")
    let nonce = bytes("cafebabefacedbaddecaf888")
    let authenticatedData = bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    let plaintext = bytes(
      "d9313225f88406e5a55909c5aff5269a"
        + "86a7a9531534f7da2e4c303d8a318a72"
        + "1c3c0c95956809532fcf0e2449a6b525"
        + "b16aedf5aa0de657ba637b39"
    )
    let expected =
      "42831ec2217774244b7221b784d0d49c"
      + "e3aa212f2c02a4e035c17e2329aca12e"
      + "21d514b25466931c7d8f6a5aac84aa05"
      + "1ba30b396a0aac973d58e091"
      + "5bc94fbc3221a5db94fae95ae7121a47"

    var sealed = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count + 16)
    var cipher = try AESGCM(key: key.span)
    try sealed.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: plaintext.span,
        authenticatedData: authenticatedData.span,
        nonce: nonce.span,
        into: &output
      )
    }
    XCTAssertEqual(hex(sealed), expected)
  }

  func testAuthenticationFailureDoesNotWritePlaintext() throws {
    let key = bytes("00000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    var input = bytes("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    input[input.count - 1] ^= 1
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: 16)
    let original = output
    var cipher = try AESGCM(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try output.withUnsafeMutableBufferPointer { buffer in
      var outputSpan = MutableSpan(_unsafeElements: buffer)
      XCTAssertThrowsError(
        try cipher.open(
          ciphertextAndTag: input.span,
          authenticatedData: Span(_unsafeElements: empty),
          nonce: nonce.span,
          into: &outputSpan
        )
      ) { error in
        XCTAssertEqual(error as? AEADError, .authenticationFailed)
      }
    }
    XCTAssertEqual(output, original)
  }

  func testExactInPlaceSealAndOpenAreSupported() throws {
    let key = bytes("00000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    let plaintext = bytes("00000000000000000000000000000000")
    var storage = ContiguousArray<UInt8>(repeating: 0, count: 32)
    storage.replaceSubrange(0..<plaintext.count, with: plaintext)
    var cipher = try AESGCM(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try storage.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: Span(
          _unsafeElements: UnsafeBufferPointer(start: buffer.baseAddress, count: plaintext.count)),
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &output
      )
    }

    try storage.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.open(
        ciphertextAndTag: Span(
          _unsafeElements: UnsafeBufferPointer(start: buffer.baseAddress, count: 32)),
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &output
      )
    }
    XCTAssertEqual(Array(storage.prefix(plaintext.count)), Array(plaintext))
  }

  func testPartialInputOutputOverlapIsRejectedBeforeMutation() throws {
    let key = bytes("00000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    var storage = ContiguousArray<UInt8>(repeating: 0x5A, count: 48)
    storage.replaceSubrange(0..<16, with: bytes("00000000000000000000000000000000"))
    let original = storage
    var cipher = try AESGCM(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try storage.withUnsafeMutableBufferPointer { buffer in
      let plaintextBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: 16
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 1),
        count: 32
      )
      var output = MutableSpan(_unsafeElements: outputBuffer)
      do {
        try cipher.seal(
          plaintext: Span(_unsafeElements: plaintextBuffer),
          authenticatedData: Span(_unsafeElements: empty),
          nonce: nonce.span,
          into: &output
        )
        XCTFail("partial input/output overlap was accepted")
      } catch AEADError.overlappingInputAndOutput {
      }
    }
    XCTAssertEqual(storage, original)
  }

  func testSupportedKeyLengths() throws {
    for count in AESGCM.supportedKeyByteCounts {
      let key = ContiguousArray<UInt8>(repeating: 0, count: count)
      do {
        _ = try AESGCM(key: key.span)
      } catch {
        XCTFail("key length \(count) was rejected: \(error)")
      }
    }
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
