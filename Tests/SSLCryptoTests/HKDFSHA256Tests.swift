import SSLCore
import XCTest

@testable import SSLCrypto

final class HKDFSHA256Tests: XCTestCase {
  private enum FixtureError: Error {
    case invalidHex
  }

  func testRFC5869SHA256KnownAnswerVectors() throws {
    try validateVector(
      inputKeyMaterial: ContiguousArray(repeating: 0x0B, count: 22),
      salt: ContiguousArray(UInt8(0x00)...UInt8(0x0C)),
      info: ContiguousArray(UInt8(0xF0)...UInt8(0xF9)),
      expectedPseudorandomKey:
        "077709362c2e32df0ddc3f0dc47bba63"
        + "90b6c73bb50f9c3122ec844ad7c2b3e5",
      expectedOutputKeyMaterial:
        "3cb25f25faacd57a90434f64d0362f2a"
        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        + "34007208d5b887185865"
    )

    try validateVector(
      inputKeyMaterial: ContiguousArray(UInt8(0x00)...UInt8(0x4F)),
      salt: ContiguousArray(UInt8(0x60)...UInt8(0xAF)),
      info: ContiguousArray(UInt8(0xB0)...UInt8(0xFF)),
      expectedPseudorandomKey:
        "06a6b88c5853361a06104c9ceb35b45c"
        + "ef760014904671014a193f40c15fc244",
      expectedOutputKeyMaterial:
        "b11e398dc80327a1c8e7f78c596a4934"
        + "4f012eda2d4efad8a050cc4c19afa97c"
        + "59045a99cac7827271cb41c65e590e09"
        + "da3275600c2f09b8367793a9aca3db71"
        + "cc30c58179ec3e87c14c01d5c1f3434f"
        + "1d87"
    )

    try validateVector(
      inputKeyMaterial: ContiguousArray(repeating: 0x0B, count: 22),
      salt: [],
      info: [],
      expectedPseudorandomKey:
        "19ef24a32c717b167f33a91d6f648bdf"
        + "96596776afdb6377ac434c1c293ccb04",
      expectedOutputKeyMaterial:
        "8da4e775a563c18f715f802a063c5a31"
        + "b8a11f5c5ee1879ec3454e5f3c738d2d"
        + "9d201395faa4b61a96c8"
    )
  }

  func testExtractRejectsUndersizedOutputBeforeWriting() throws {
    let inputKeyMaterial = ContiguousArray(repeating: UInt8(0x0B), count: 22)
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: HKDFSHA256.pseudorandomKeyByteCount - 1
    )

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &outputSpan
      )
      XCTFail("HKDF extract accepted an undersized output")
    } catch {
      XCTAssertEqual(
        error,
        .invalidPseudorandomKeyOutputLength(
          expected: HKDFSHA256.pseudorandomKeyByteCount,
          actual: HKDFSHA256.pseudorandomKeyByteCount - 1
        )
      )
    }

    XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
  }

  func testExtractRejectsOversizedOutputBeforeWriting() throws {
    let inputKeyMaterial = ContiguousArray(repeating: UInt8(0x0B), count: 22)
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: HKDFSHA256.pseudorandomKeyByteCount + 7
    )

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &outputSpan
      )
      XCTFail("HKDF extract accepted an oversized output")
    } catch {
      XCTAssertEqual(
        error,
        .invalidPseudorandomKeyOutputLength(
          expected: HKDFSHA256.pseudorandomKeyByteCount,
          actual: HKDFSHA256.pseudorandomKeyByteCount + 7
        )
      )
    }

    XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
  }

  func testExtractRejectsInputKeyMaterialOutputOverlapBeforeWriting() throws {
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    var storage = ContiguousArray<UInt8>(
      repeating: 0x0B,
      count: HKDFSHA256.pseudorandomKeyByteCount + 8
    )

    try storage.withUnsafeMutableBufferPointer {
      buffer throws(HKDFError) in
      let inputBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: 22
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 8),
        count: HKDFSHA256.pseudorandomKeyByteCount
      )
      let inputKeyMaterial = Span(_unsafeElements: inputBuffer)
      var output = MutableSpan(_unsafeElements: outputBuffer)

      do {
        try HKDFSHA256.extract(
          inputKeyMaterial: inputKeyMaterial,
          salt: salt.span,
          into: &output
        )
        XCTFail("HKDF extract accepted overlapping IKM and output")
      } catch HKDFError.overlappingInputAndOutput {
      } catch {
        XCTFail("HKDF extract threw an unexpected error: \(error)")
      }
    }

    XCTAssertTrue(storage.allSatisfy { $0 == 0x0B })
  }

  func testExtractRejectsSaltOutputOverlapBeforeWriting() throws {
    let inputKeyMaterial = ContiguousArray(
      repeating: UInt8(0x0B),
      count: 22
    )
    var storage = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: HKDFSHA256.pseudorandomKeyByteCount + 4
    )

    try storage.withUnsafeMutableBufferPointer {
      buffer throws(HKDFError) in
      let saltBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: 13
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 4),
        count: HKDFSHA256.pseudorandomKeyByteCount
      )
      let salt = Span(_unsafeElements: saltBuffer)
      var output = MutableSpan(_unsafeElements: outputBuffer)

      do {
        try HKDFSHA256.extract(
          inputKeyMaterial: inputKeyMaterial.span,
          salt: salt,
          into: &output
        )
        XCTFail("HKDF extract accepted overlapping salt and output")
      } catch HKDFError.overlappingInputAndOutput {
      } catch {
        XCTFail("HKDF extract threw an unexpected error: \(error)")
      }
    }

    XCTAssertTrue(storage.allSatisfy { $0 == 0x5A })
  }

  func testExpandRejectsShortPseudorandomKeyBeforeWriting() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount - 1
    )
    let info = ContiguousArray("context".utf8)
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: 42)

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &outputSpan
      )
      XCTFail("HKDF expand accepted a short pseudorandom key")
    } catch {
      XCTAssertEqual(
        error,
        .pseudorandomKeyTooShort(
          minimum: HKDFSHA256.pseudorandomKeyByteCount,
          actual: HKDFSHA256.pseudorandomKeyByteCount - 1
        )
      )
    }

    XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
  }

  func testExpandRejectsExcessiveOutputBeforeWriting() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    let info = ContiguousArray("context".utf8)
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: HKDFSHA256.maximumOutputByteCount + 1
    )

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &outputSpan
      )
      XCTFail("HKDF expand accepted excessive output")
    } catch {
      XCTAssertEqual(
        error,
        .outputTooLong(
          limit: HKDFSHA256.maximumOutputByteCount,
          actual: HKDFSHA256.maximumOutputByteCount + 1
        )
      )
    }

    XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
  }

  func testExpandAcceptsZeroLengthOutput() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    let info = ContiguousArray("context".utf8)
    var output = ContiguousArray<UInt8>()

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &outputSpan
      )
    }

    XCTAssertTrue(output.isEmpty)
  }

  func testExpandAcceptsMaximumOutputAndUsesCounter255() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    let info = ContiguousArray("context".utf8)
    let expectedFirstBlock = try bytes(
      fromHex:
        "1fe2ff335140507db67e6c7c080a1676"
        + "db17e0e379dd4f46cf82bfb60567883b"
    )
    let expectedLastBlock = try bytes(
      fromHex:
        "8aecfc06e61425161392295533604013"
        + "e3c41d0bc8fae8414e236ee368d620ea"
    )
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: HKDFSHA256.maximumOutputByteCount
    )

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &outputSpan
      )
    }

    XCTAssertEqual(
      ContiguousArray(
        output.prefix(HKDFSHA256.pseudorandomKeyByteCount)
      ),
      expectedFirstBlock
    )
    XCTAssertEqual(
      ContiguousArray(
        output.suffix(HKDFSHA256.pseudorandomKeyByteCount)
      ),
      expectedLastBlock
    )
  }

  func testExpandAcceptsMaximumPartialOutputAndUsesCounter255() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    let info = ContiguousArray("context".utf8)
    let expectedLastPartialBlock = try bytes(
      fromHex:
        "8aecfc06e61425161392295533604013"
        + "e3c41d0bc8fae8414e236ee368d620"
    )
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: HKDFSHA256.maximumOutputByteCount - 1
    )

    do {
      var outputSpan = output.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &outputSpan
      )
    }

    XCTAssertEqual(
      ContiguousArray(output.suffix(expectedLastPartialBlock.count)),
      expectedLastPartialBlock
    )
  }

  func testExpandBoundaryLengthsWithLongPseudorandomKey() throws {
    let pseudorandomKey = ContiguousArray(UInt8(0x00)...UInt8(0x4F))
    let info = ContiguousArray("context".utf8)
    let expected = try bytes(
      fromHex:
        "112cbf0a832a3877f70a265eb28ff3a9"
        + "86d6042b6b5e58f88e5559929c8aeb8b"
        + "bd22df4140c3041945710e8f7d310e9d"
        + "abf2900ccf93d81c1b8b3e63651ccece"
        + "52"
    )
    let outputByteCounts = [1, 31, 32, 33, 64, 65]

    for outputByteCount in outputByteCounts {
      var output = ContiguousArray<UInt8>(
        repeating: 0,
        count: outputByteCount
      )
      do {
        var outputSpan = output.mutableSpan
        try HKDFSHA256.expand(
          pseudorandomKey: pseudorandomKey.span,
          info: info.span,
          into: &outputSpan
        )
      }
      XCTAssertEqual(
        output,
        ContiguousArray(expected.prefix(outputByteCount))
      )
    }
  }

  func testExpandRejectsPseudorandomKeyOutputOverlapBeforeWriting() throws {
    let info = ContiguousArray("context".utf8)
    var storage = ContiguousArray<UInt8>(repeating: 0x3C, count: 58)

    try storage.withUnsafeMutableBufferPointer {
      buffer throws(HKDFError) in
      let pseudorandomKeyBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: HKDFSHA256.pseudorandomKeyByteCount
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 16),
        count: 42
      )
      let pseudorandomKey = Span(
        _unsafeElements: pseudorandomKeyBuffer
      )
      var output = MutableSpan(_unsafeElements: outputBuffer)

      do {
        try HKDFSHA256.expand(
          pseudorandomKey: pseudorandomKey,
          info: info.span,
          into: &output
        )
        XCTFail("HKDF expand accepted overlapping PRK and output")
      } catch HKDFError.overlappingInputAndOutput {
      } catch {
        XCTFail("HKDF expand threw an unexpected error: \(error)")
      }
    }

    XCTAssertTrue(storage.allSatisfy { $0 == 0x3C })
  }

  func testExpandRejectsInfoOutputOverlapBeforeWriting() throws {
    let pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0x3C,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    var storage = ContiguousArray<UInt8>(repeating: 0x5A, count: 46)

    try storage.withUnsafeMutableBufferPointer {
      buffer throws(HKDFError) in
      let infoBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: 7
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(by: 4),
        count: 42
      )
      let info = Span(_unsafeElements: infoBuffer)
      var output = MutableSpan(_unsafeElements: outputBuffer)

      do {
        try HKDFSHA256.expand(
          pseudorandomKey: pseudorandomKey.span,
          info: info,
          into: &output
        )
        XCTFail("HKDF expand accepted overlapping info and output")
      } catch HKDFError.overlappingInputAndOutput {
      } catch {
        XCTFail("HKDF expand threw an unexpected error: \(error)")
      }
    }

    XCTAssertTrue(storage.allSatisfy { $0 == 0x5A })
  }

  func testExpandAcceptsExactlyAdjacentInputAndOutput() throws {
    let info = ContiguousArray("context".utf8)
    let expected = try bytes(
      fromHex:
        "1fe2ff335140507db67e6c7c080a1676"
        + "db17e0e379dd4f46cf82bfb60567883b"
        + "e6d264e4b66a72503e99"
    )
    let outputByteCount = expected.count
    var storage = ContiguousArray<UInt8>(
      repeating: 0,
      count: HKDFSHA256.pseudorandomKeyByteCount + outputByteCount
    )
    var keyIndex = 0
    while keyIndex < HKDFSHA256.pseudorandomKeyByteCount {
      storage[keyIndex] = 0x3C
      keyIndex += 1
    }

    try storage.withUnsafeMutableBufferPointer { buffer in
      let pseudorandomKeyBuffer = UnsafeBufferPointer(
        start: UnsafePointer(buffer.baseAddress!),
        count: HKDFSHA256.pseudorandomKeyByteCount
      )
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!.advanced(
          by: HKDFSHA256.pseudorandomKeyByteCount
        ),
        count: outputByteCount
      )
      let pseudorandomKey = Span(
        _unsafeElements: pseudorandomKeyBuffer
      )
      var output = MutableSpan(_unsafeElements: outputBuffer)

      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey,
        info: info.span,
        into: &output
      )
    }

    XCTAssertTrue(
      storage.prefix(HKDFSHA256.pseudorandomKeyByteCount)
        .allSatisfy { $0 == 0x3C }
    )
    XCTAssertEqual(
      ContiguousArray(
        storage.dropFirst(HKDFSHA256.pseudorandomKeyByteCount)
      ),
      expected
    )
  }

  func testExpandAcceptsReverseAdjacentOutputAndInput() throws {
    let info = ContiguousArray("context".utf8)
    let expected = try bytes(
      fromHex:
        "1fe2ff335140507db67e6c7c080a1676"
        + "db17e0e379dd4f46cf82bfb60567883b"
        + "e6d264e4b66a72503e99"
    )
    let outputByteCount = expected.count
    var storage = ContiguousArray<UInt8>(
      repeating: 0,
      count: outputByteCount + HKDFSHA256.pseudorandomKeyByteCount
    )
    var keyIndex = outputByteCount
    while keyIndex < storage.count {
      storage[keyIndex] = 0x3C
      keyIndex += 1
    }

    try storage.withUnsafeMutableBufferPointer { buffer in
      let outputBuffer = UnsafeMutableBufferPointer(
        start: buffer.baseAddress!,
        count: outputByteCount
      )
      let pseudorandomKeyBuffer = UnsafeBufferPointer(
        start: UnsafePointer(
          buffer.baseAddress!.advanced(by: outputByteCount)
        ),
        count: HKDFSHA256.pseudorandomKeyByteCount
      )
      let pseudorandomKey = Span(
        _unsafeElements: pseudorandomKeyBuffer
      )
      var output = MutableSpan(_unsafeElements: outputBuffer)

      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey,
        info: info.span,
        into: &output
      )
    }

    XCTAssertEqual(
      ContiguousArray(storage.prefix(outputByteCount)),
      expected
    )
    XCTAssertTrue(
      storage.suffix(HKDFSHA256.pseudorandomKeyByteCount)
        .allSatisfy { $0 == 0x3C }
    )
  }

  private func validateVector(
    inputKeyMaterial: ContiguousArray<UInt8>,
    salt: ContiguousArray<UInt8>,
    info: ContiguousArray<UInt8>,
    expectedPseudorandomKey: String,
    expectedOutputKeyMaterial: String
  ) throws {
    let expectedPseudorandomKey = try bytes(
      fromHex: expectedPseudorandomKey
    )
    let expectedOutputKeyMaterial = try bytes(
      fromHex: expectedOutputKeyMaterial
    )
    var pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0,
      count: HKDFSHA256.pseudorandomKeyByteCount
    )
    do {
      var output = pseudorandomKey.mutableSpan
      try HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &output
      )
    }
    XCTAssertEqual(pseudorandomKey, expectedPseudorandomKey)

    var outputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0,
      count: expectedOutputKeyMaterial.count
    )
    do {
      var output = outputKeyMaterial.mutableSpan
      try HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &output
      )
    }
    XCTAssertEqual(outputKeyMaterial, expectedOutputKeyMaterial)
  }

  private func bytes(
    fromHex string: String
  ) throws -> ContiguousArray<UInt8> {
    let encoded = ContiguousArray(string.utf8)
    guard encoded.count.isMultiple(of: 2) else {
      throw FixtureError.invalidHex
    }

    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(encoded.count / 2)
    var index = 0
    while index < encoded.count {
      guard
        let high = hexadecimalValue(encoded[index]),
        let low = hexadecimalValue(encoded[index + 1])
      else {
        throw FixtureError.invalidHex
      }
      bytes.append((high << 4) | low)
      index += 2
    }
    return bytes
  }

  private func hexadecimalValue(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39:
      byte - 0x30
    case 0x61...0x66:
      byte - 0x61 + 10
    case 0x41...0x46:
      byte - 0x41 + 10
    default:
      nil
    }
  }
}
