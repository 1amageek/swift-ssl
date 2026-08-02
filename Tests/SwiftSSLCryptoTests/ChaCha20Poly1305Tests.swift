import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class ChaCha20Poly1305Tests: XCTestCase {
  func testRFC8439KnownAnswerVector() throws {
    let key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    let nonce = bytes("070000004041424344454647")
    let authenticatedData = bytes("50515253c0c1c2c3c4c5c6c7")
    let plaintext = ContiguousArray(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        .utf8
    )
    let expected = bytes(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    )

    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    let cipher = try ChaCha20Poly1305(key: key.span)
    try sealed.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: plaintext.span,
        authenticatedData: authenticatedData.span,
        nonce: nonce.span,
        into: &output
      )
    }
    XCTAssertEqual(sealed, expected)

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    try recovered.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.open(
        ciphertextAndTag: sealed.span,
        authenticatedData: authenticatedData.span,
        nonce: nonce.span,
        into: &output
      )
    }
    XCTAssertEqual(recovered, plaintext)
  }

  func testAuthenticationFailureDoesNotWritePlaintext() throws {
    let key = bytes("0000000000000000000000000000000000000000000000000000000000000000")
    let nonce = bytes("000000000000000000000000")
    let plaintext = bytes("00000000000000000000000000000000")
    let authenticatedData = bytes("01020304")
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count + 16)
    let cipher = try ChaCha20Poly1305(key: key.span)
    try sealed.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      try cipher.seal(
        plaintext: plaintext.span,
        authenticatedData: authenticatedData.span,
        nonce: nonce.span,
        into: &output
      )
    }
    sealed[sealed.count - 1] ^= 1

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    let original = recovered
    try recovered.withUnsafeMutableBufferPointer { buffer in
      var output = MutableSpan(_unsafeElements: buffer)
      XCTAssertThrowsError(
        try cipher.open(
          ciphertextAndTag: sealed.span,
          authenticatedData: authenticatedData.span,
          nonce: nonce.span,
          into: &output
        )
      ) { error in
        XCTAssertEqual(error as? AEADError, .authenticationFailed)
      }
    }
    XCTAssertEqual(recovered, original)
  }

  func testExactInPlaceSealAndOpen() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>(repeating: 0x42, count: 64)
    var storage = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count + 16)
    storage.replaceSubrange(0..<plaintext.count, with: plaintext)
    let cipher = try ChaCha20Poly1305(key: key.span)
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
          _unsafeElements: UnsafeBufferPointer(
            start: buffer.baseAddress, count: plaintext.count + 16)),
        authenticatedData: Span(_unsafeElements: empty),
        nonce: nonce.span,
        into: &output
      )
    }
    XCTAssertEqual(Array(storage.prefix(plaintext.count)), Array(plaintext))
  }

  func testPartialOverlapIsRejectedBeforeMutation() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    var storage = ContiguousArray<UInt8>(repeating: 0x5A, count: 96)
    let original = storage
    let cipher = try ChaCha20Poly1305(key: key.span)
    let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)

    try storage.withUnsafeMutableBufferPointer { buffer in
      let plaintext = UnsafeBufferPointer(start: UnsafePointer(buffer.baseAddress!), count: 64)
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 1), count: 80)
      var output = MutableSpan(_unsafeElements: outputBuffer)
      do {
        try cipher.seal(
          plaintext: Span(_unsafeElements: plaintext),
          authenticatedData: Span(_unsafeElements: empty),
          nonce: nonce.span,
          into: &output
        )
        XCTFail("partial overlap was accepted")
      } catch AEADError.overlappingInputAndOutput {
      }
    }
    XCTAssertEqual(storage, original)
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
}
