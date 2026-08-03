import SSLCore
import XCTest

@testable import SSLCrypto

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
    let cipher = try AESGCM(key: key.span)
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
    let cipher = try AESGCM(key: key.span)
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
    let cipher = try AESGCM(key: key.span)
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
    let cipher = try AESGCM(key: key.span)
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
    let cipher = try AESGCM(key: key.span)
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
    let cipher = try AESGCM(key: key.span)
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

  #if canImport(Darwin) && arch(arm64) && canImport(simd)
    func testARM64GHASHMultiplyMatchesBitSerialReference() {
      var state: UInt64 = 0x243f_6a88_85a3_08d3
      func nextWord() -> UInt64 {
        state = state &* 0xd134_2543_de82_ef95 &+ 0x1319_8a2e_0370_7344
        return state
      }

      for _ in 0..<1_000 {
        let x = (nextWord(), nextWord())
        let hash = (nextWord(), nextWord())
        let expected = bitSerialGHASHMultiply(x: x, hash: hash)
        let actual = GHASHARM64Kernel.multiply(
          xHigh: x.0,
          xLow: x.1,
          hashHigh: hash.0,
          hashLow: hash.1
        )
        XCTAssertEqual(actual.0, expected.0)
        XCTAssertEqual(actual.1, expected.1)
      }
    }

    func testARM64FourBlockGHASHMatchesSequentialEvaluation() {
      var state: UInt64 = 0x9e37_79b9_7f4a_7c15
      func nextWord() -> UInt64 {
        state = state &* 0xd134_2543_de82_ef95 &+ 0xa409_3822_299f_31d0
        return state
      }

      for _ in 0..<1_000 {
        let hash = (nextWord(), nextWord())
        let blocks = SIMD8<UInt64>(
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord()
        )
        let accumulator = (nextWord(), nextWord())

        var expected = GHASHARM64Kernel.multiply(
          xHigh: accumulator.0 ^ blocks[0],
          xLow: accumulator.1 ^ blocks[1],
          hashHigh: hash.0,
          hashLow: hash.1
        )
        var blockIndex = 1
        while blockIndex < 4 {
          expected = GHASHARM64Kernel.multiply(
            xHigh: expected.0 ^ blocks[blockIndex * 2],
            xLow: expected.1 ^ blocks[blockIndex * 2 + 1],
            hashHigh: hash.0,
            hashLow: hash.1
          )
          blockIndex += 1
        }
        let actual = GHASHARM64Kernel.multiplyFour(
          accumulatorHigh: accumulator.0,
          accumulatorLow: accumulator.1,
          blocks: blocks,
          reversedHashPowers: GHASHARM64Kernel.makeReversedHashPowers(
            hashHigh: hash.0,
            hashLow: hash.1
          )
        )
        XCTAssertEqual(actual.0, expected.0)
        XCTAssertEqual(actual.1, expected.1)
      }
    }

    func testARM64EightBlockGHASHMatchesSequentialEvaluation() {
      var state: UInt64 = 0x243f_6a88_85a3_08d3
      func nextWord() -> UInt64 {
        state = state &* 0x9e37_79b9_7f4a_7c15 &+ 0x1319_8a2e_0370_7344
        return state
      }

      for _ in 0..<1_000 {
        let hash = (nextWord(), nextWord())
        let blocks = SIMD16<UInt64>(
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord(),
          nextWord(), nextWord()
        )
        let accumulator = (nextWord(), nextWord())

        var expected = GHASHARM64Kernel.multiply(
          xHigh: accumulator.0 ^ blocks[0],
          xLow: accumulator.1 ^ blocks[1],
          hashHigh: hash.0,
          hashLow: hash.1
        )
        var blockIndex = 1
        while blockIndex < 8 {
          expected = GHASHARM64Kernel.multiply(
            xHigh: expected.0 ^ blocks[blockIndex * 2],
            xLow: expected.1 ^ blocks[blockIndex * 2 + 1],
            hashHigh: hash.0,
            hashLow: hash.1
          )
          blockIndex += 1
        }
        let firstFour = GHASHARM64Kernel.makeReversedHashPowers(
          hashHigh: hash.0,
          hashLow: hash.1
        )
        let actual = GHASHARM64Kernel.multiplyEight(
          accumulatorHigh: accumulator.0,
          accumulatorLow: accumulator.1,
          blocks: blocks,
          reversedHashPowers: GHASHARM64Kernel.makeEightReversedHashPowers(firstFour)
        )
        XCTAssertEqual(actual.0, expected.0)
        XCTAssertEqual(actual.1, expected.1)
      }
    }

    private func bitSerialGHASHMultiply(
      x: (UInt64, UInt64),
      hash: (UInt64, UInt64)
    ) -> (UInt64, UInt64) {
      var resultHigh: UInt64 = 0
      var resultLow: UInt64 = 0
      var valueHigh = hash.0
      var valueLow = hash.1
      var bitIndex = 0
      while bitIndex < 128 {
        let bit: UInt64
        if bitIndex < 64 {
          bit = (x.0 >> UInt64(63 - bitIndex)) & 1
        } else {
          bit = (x.1 >> UInt64(127 - bitIndex)) & 1
        }
        let selectionMask = UInt64(0) &- bit
        resultHigh ^= valueHigh & selectionMask
        resultLow ^= valueLow & selectionMask

        let reductionMask = UInt64(0) &- (valueLow & 1)
        valueLow = (valueLow >> 1) | (valueHigh << 63)
        valueHigh = (valueHigh >> 1) ^ (0xe100_0000_0000_0000 & reductionMask)
        bitIndex += 1
      }
      return (resultHigh, resultLow)
    }
  #endif

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
