import SSLCore
import XCTest

@testable import SSLCrypto

final class SHA256Tests: XCTestCase {
  func testKnownAnswerVectors() throws {
    let vectors: [(input: ContiguousArray<UInt8>, digest: String)] = [
      ([], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
      (
        ContiguousArray("abc".utf8),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      ),
      (
        ContiguousArray(
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
      ),
    ]

    for vector in vectors {
      XCTAssertEqual(try digestHex(of: vector.input), vector.digest)
    }
  }

  func testMillionByteKnownAnswerVector() throws {
    let chunk = ContiguousArray<UInt8>(repeating: 0x61, count: 1_000)
    var context = SHA256.makeContext()

    for _ in 0..<1_000 {
      try context.update(chunk.span)
    }

    let digest = try finalizeHex(context)
    XCTAssertEqual(
      digest,
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )
  }

  func testBoundaryLengthKnownAnswerVectors() throws {
    let vectors: [(byteCount: Int, digest: String)] = [
      (55, "c096925d8ee622ec75c396b1712bcb599952e05c2cd1f3e33032514893edbc83"),
      (56, "4e3bd718369bf855312b6fae0e874c697a5c910c0270ebab390f15872a7878a5"),
      (63, "e5e8e5e7481532428a3d324d4163fe92fea5f52e85fbe33abfa5aa9235c5addf"),
      (64, "f616afd08efb65e91c7fa856fff5e2b991980c5b3fbdffb81f1e4d9dbdb509d7"),
      (65, "8ce44bf6e55d58f6f5fa326e9fa574cf8fd80adcaf299d4b2f93e9b7414a9821"),
      (127, "45cfe66b76289d753ceee6558f70d82af6b8c590265cacb2d4aa11f3b0396fb0"),
      (128, "fdb50d75cc2ca56537d86f78e871f423691c3822ad1ac9653e84ab9781328f9f"),
      (129, "7b69204869f4800e543ca75165bbe5b2d5dab3379c9b5f6caacfd36888958834"),
      (192, "a734533331ac2f324dfaa70ae66f6b40fc34982d0935552cc28f6c2ccbdefad8"),
      (1_024, "56e147db975bb990f6551ba56b4a631a692419d75cc2c12c83c65203bdd9240c"),
    ]

    for vector in vectors {
      XCTAssertEqual(
        try digestHex(of: makePattern(byteCount: vector.byteCount)),
        vector.digest,
        "Unexpected digest for \(vector.byteCount) bytes"
      )
    }
  }

  func testIncrementalBoundaryUpdatesMatchKnownAnswer() throws {
    let input = makePattern(byteCount: 129)
    let chunkByteCounts = [1, 62, 2, 64]
    var context = SHA256.makeContext()
    var offset = 0

    for chunkByteCount in chunkByteCounts {
      let endOffset = offset + chunkByteCount
      try context.update(input.span.extracting(offset..<endOffset))
      offset = endOffset
    }

    XCTAssertEqual(offset, input.count)
    let digest = try finalizeHex(context)
    XCTAssertEqual(
      digest,
      "7b69204869f4800e543ca75165bbe5b2d5dab3379c9b5f6caacfd36888958834"
    )
  }

  func testClonedContextsDivergeWithoutSharingState() throws {
    let prefix = ContiguousArray("prefix:".utf8)
    let leftSuffix = ContiguousArray("left".utf8)
    let rightSuffix = ContiguousArray("right".utf8)
    var context = SHA256.makeContext()
    try context.update(prefix.span)

    var left = context.clone()
    var right = context.clone()
    try left.update(leftSuffix.span)
    try right.update(rightSuffix.span)

    let leftDigest = try finalizeHex(left)
    let rightDigest = try finalizeHex(right)
    XCTAssertNotEqual(leftDigest, rightDigest)
    XCTAssertEqual(
      leftDigest,
      try digestHex(of: ContiguousArray("prefix:left".utf8))
    )
    XCTAssertEqual(
      rightDigest,
      try digestHex(of: ContiguousArray("prefix:right".utf8))
    )
  }

  func testIncrementalRejectsNonExactOutputWithoutModification() throws {
    let input = ContiguousArray("abc".utf8)
    for outputByteCount in [31, 33] {
      var context = SHA256.makeContext()
      try context.update(input.span)
      var output = ContiguousArray<UInt8>(
        repeating: 0xA5,
        count: outputByteCount
      )

      do {
        var outputSpan = output.mutableSpan
        try context.finalize(into: &outputSpan)
        XCTFail("SHA-256 finalized into a non-exact output")
      } catch {
        XCTAssertEqual(
          error,
          .invalidOutputLength(expected: 32, actual: outputByteCount)
        )
      }

      XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
    }
  }

  func testOneShotRejectsNonExactOutputWithoutModification() {
    let input = ContiguousArray("abc".utf8)
    for outputByteCount in [31, 33] {
      var output = ContiguousArray<UInt8>(
        repeating: 0xA5,
        count: outputByteCount
      )

      do {
        var outputSpan = output.mutableSpan
        try SHA256.hash(input.span, into: &outputSpan)
        XCTFail("SHA-256 hashed into a non-exact output")
      } catch {
        XCTAssertEqual(
          error,
          .invalidOutputLength(expected: 32, actual: outputByteCount)
        )
      }

      XCTAssertTrue(output.allSatisfy { $0 == 0xA5 })
    }
  }

  func testInputLengthValidationRejectsOverflowWithoutTrapping() throws {
    let maximumInputByteCount = UInt64.max >> 3

    XCTAssertThrowsError(
      try SHA256Context.validateAdditionalInputByteCount(
        maximumInputByteCount + 1,
        currentByteCount: 0
      )
    ) { error in
      XCTAssertEqual(
        error as? CryptoInputError,
        .inputTooLong(limit: maximumInputByteCount)
      )
    }

    XCTAssertThrowsError(
      try SHA256Context.validateAdditionalInputByteCount(
        1,
        currentByteCount: maximumInputByteCount
      )
    ) { error in
      XCTAssertEqual(
        error as? CryptoInputError,
        .inputTooLong(limit: maximumInputByteCount)
      )
    }

    try SHA256Context.validateAdditionalInputByteCount(
      0,
      currentByteCount: maximumInputByteCount
    )
  }

  #if os(macOS) && arch(arm64) && canImport(simd)
    func testARM64KernelMatchesScalarKernel() {
      var seed: UInt64 = 0x9E37_79B9_7F4A_7C15

      for _ in 0..<128 {
        var state = SIMD8<UInt32>(repeating: 0)
        var schedule = SIMD16<UInt32>(repeating: 0)

        for index in 0..<8 {
          state[index] = nextWord(seed: &seed)
        }
        for index in 0..<16 {
          schedule[index] = nextWord(seed: &seed)
        }

        var scalarState = state
        var acceleratedState = state
        SHA256Compression.compressUsingScalar(
          state: &scalarState,
          initialSchedule: schedule
        )
        SHA256Compression.compressUsingARM64SHA2(
          state: &acceleratedState,
          initialSchedule: schedule
        )

        XCTAssertEqual(acceleratedState, scalarState)
      }
    }

    func testARM64MultiBlockKernelMatchesScalarForUnalignedInputs() {
      var seed: UInt64 = 0xD1B5_4A32_D192_ED03

      for blockCount in [2, 3, 16] {
        for byteOffset in 0..<16 {
          let bytes = makePattern(
            byteCount: byteOffset + blockCount * 64
          )
          var initialState = SIMD8<UInt32>(repeating: 0)
          for stateIndex in 0..<8 {
            initialState[stateIndex] = nextWord(seed: &seed)
          }

          var scalarState = initialState
          for blockIndex in 0..<blockCount {
            SHA256Compression.compressUsingScalar(
              state: &scalarState,
              initialSchedule: initialSchedule(
                bytes,
                at: byteOffset + blockIndex * 64
              )
            )
          }

          var acceleratedState = initialState
          // The contiguous array owns every initialized source byte for
          // this synchronous borrow. The tested offset and block count
          // keep all 64-byte reads in bounds, and the pointer does not
          // escape or cross a Sendable boundary.
          bytes.withUnsafeBufferPointer { buffer in
            SHA256ARM64Kernel.compressBlocks(
              state: &acceleratedState,
              blocks: UnsafeRawPointer(
                buffer.baseAddress.unsafelyUnwrapped
              ).advanced(by: byteOffset),
              blockCount: blockCount
            )
          }

          XCTAssertEqual(
            acceleratedState,
            scalarState,
            "Mismatch at offset \(byteOffset), blocks \(blockCount)"
          )
        }
      }
    }
  #endif

  private func digestHex(
    of input: ContiguousArray<UInt8>
  ) throws -> String {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
    do {
      var outputSpan = output.mutableSpan
      try SHA256.hash(input.span, into: &outputSpan)
    }
    return hexString(output)
  }

  private func finalizeHex(
    _ context: consuming SHA256Context
  ) throws -> String {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
    do {
      var outputSpan = output.mutableSpan
      try context.finalize(into: &outputSpan)
    }
    return hexString(output)
  }

  private func hexString(_ bytes: ContiguousArray<UInt8>) -> String {
    let digits: ContiguousArray<UInt8> = ContiguousArray(
      "0123456789abcdef".utf8
    )
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(bytes.count * 2)
    for byte in bytes {
      encoded.append(digits[Int(byte >> 4)])
      encoded.append(digits[Int(byte & 0x0F)])
    }
    return String(decoding: encoded, as: UTF8.self)
  }

  private func makePattern(
    byteCount: Int
  ) -> ContiguousArray<UInt8> {
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(byteCount)
    var index = 0
    while index < byteCount {
      bytes.append(UInt8(truncatingIfNeeded: index &* 31 &+ 17))
      index += 1
    }
    return bytes
  }

  private func initialSchedule(
    _ bytes: ContiguousArray<UInt8>,
    at byteOffset: Int
  ) -> SIMD16<UInt32> {
    var schedule = SIMD16<UInt32>(repeating: 0)
    var wordIndex = 0
    while wordIndex < 16 {
      let offset = byteOffset + wordIndex * 4
      schedule[wordIndex] =
        (UInt32(bytes[offset]) << 24)
        | (UInt32(bytes[offset + 1]) << 16)
        | (UInt32(bytes[offset + 2]) << 8)
        | UInt32(bytes[offset + 3])
      wordIndex += 1
    }
    return schedule
  }

  private func nextWord(seed: inout UInt64) -> UInt32 {
    seed ^= seed << 13
    seed ^= seed >> 7
    seed ^= seed << 17
    return UInt32(truncatingIfNeeded: seed)
  }
}
