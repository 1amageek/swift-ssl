import SSLCore
import XCTest

@testable import SSLCrypto

final class SHA3Tests: XCTestCase {
  func testSHA3EmptyKnownAnswers() throws {
    var sha3_256 = ContiguousArray<UInt8>(repeating: 0, count: SHA3_256.digestByteCount)
    var sha3_256Output = sha3_256.mutableSpan
    try SHA3_256.hash(ContiguousArray<UInt8>().span, into: &sha3_256Output)
    XCTAssertEqual(
      copy(sha3_256.span), bytes("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    )

    var sha3_384 = ContiguousArray<UInt8>(repeating: 0, count: SHA3_384.digestByteCount)
    var sha3_384Output = sha3_384.mutableSpan
    try SHA3_384.hash(ContiguousArray<UInt8>().span, into: &sha3_384Output)
    XCTAssertEqual(
      copy(sha3_384.span),
      bytes(
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
      )
    )

    var sha3_512 = ContiguousArray<UInt8>(repeating: 0, count: SHA3_512.digestByteCount)
    var sha3_512Output = sha3_512.mutableSpan
    try SHA3_512.hash(ContiguousArray<UInt8>().span, into: &sha3_512Output)
    XCTAssertEqual(
      copy(sha3_512.span),
      bytes(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
      ))
  }

  func testSHA3IncrementalClone() throws {
    var context = SHA3_256.makeContext()
    try context.update(ContiguousArray<UInt8>([0x61]).span)
    var clone = context.clone()
    try context.update(ContiguousArray<UInt8>([0x62, 0x63]).span)
    try clone.update(ContiguousArray<UInt8>([0x62, 0x63]).span)

    var first = ContiguousArray<UInt8>(repeating: 0, count: SHA3_256.digestByteCount)
    var second = ContiguousArray<UInt8>(repeating: 0, count: SHA3_256.digestByteCount)
    var firstOutput = first.mutableSpan
    var secondOutput = second.mutableSpan
    try context.finalize(into: &firstOutput)
    try clone.finalize(into: &secondOutput)
    XCTAssertEqual(first, second)
    XCTAssertEqual(
      copy(first.span), bytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"))
  }

  func testSHAKEKnownAnswersAndOutputLengthValidation() throws {
    var shake128 = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var shake128Output = shake128.mutableSpan
    try SHAKE128.hash(
      ContiguousArray<UInt8>().span,
      outputByteCount: 32,
      into: &shake128Output
    )
    XCTAssertEqual(
      copy(shake128.span), bytes("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    )

    var shake256 = ContiguousArray<UInt8>(repeating: 0, count: 64)
    var shake256Output = shake256.mutableSpan
    try SHAKE256.hash(
      ContiguousArray<UInt8>().span,
      outputByteCount: 64,
      into: &shake256Output
    )
    XCTAssertEqual(
      copy(shake256.span),
      bytes(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
      ))

    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: 8)
    var invalidOutput = output.mutableSpan
    do {
      try SHAKE128.hash(
        ContiguousArray<UInt8>().span,
        outputByteCount: 7,
        into: &invalidOutput
      )
      XCTFail("SHAKE accepted an output length different from the requested length")
    } catch {
      XCTAssertEqual(error, .invalidOutputLength(expected: 7, actual: 8))
      XCTAssertEqual(output, ContiguousArray(repeating: 0xA5, count: 8))
    }
  }

  func testKeccakCoreIncrementalSqueezeMatchesOneShotSHAKE() throws {
    let input = ContiguousArray<UInt8>([0x61, 0x62, 0x63])
    var expected = ContiguousArray<UInt8>(repeating: 0, count: 400)
    var expectedOutput = expected.mutableSpan
    try SHAKE128.hash(input.span, outputByteCount: 400, into: &expectedOutput)

    var core = KeccakCore(rateByteCount: 168, domainSeparator: 0x1F)
    try core.update(input.span)
    var actual = ContiguousArray<UInt8>(repeating: 0, count: 400)
    do {
      var storage = actual.mutableSpan
      var chunk = storage._mutatingExtracting(0..<17)
      core.squeeze(into: &chunk)
    }
    do {
      var storage = actual.mutableSpan
      var chunk = storage._mutatingExtracting(17..<168)
      core.squeeze(into: &chunk)
    }
    do {
      var storage = actual.mutableSpan
      var chunk = storage._mutatingExtracting(168..<169)
      core.squeeze(into: &chunk)
    }
    do {
      var storage = actual.mutableSpan
      var chunk = storage._mutatingExtracting(169..<400)
      core.squeeze(into: &chunk)
    }

    XCTAssertEqual(actual, expected)
  }

  func testKeccakDirectAbsorptionMatchesOneShotAcrossRateBoundaries() throws {
    var input = ContiguousArray<UInt8>()
    input.reserveCapacity(409)
    var index = 0
    while index < 409 {
      input.append(UInt8(truncatingIfNeeded: index &* 197 &+ 29))
      index += 1
    }

    var expected = ContiguousArray<UInt8>(repeating: 0, count: SHA3_256.digestByteCount)
    var expectedOutput = expected.mutableSpan
    try SHA3_256.hash(input.span, into: &expectedOutput)

    let splitPoints = [0, 1, 7, 8, 135, 136, 137, 271, 272, 273, 408, 409]
    for firstSplit in splitPoints {
      for secondSplit in splitPoints where secondSplit >= firstSplit {
        var core = KeccakCore(rateByteCount: 136, domainSeparator: 0x06)
        try core.update(input.span.extracting(0..<firstSplit))
        try core.update(input.span.extracting(firstSplit..<secondSplit))
        try core.update(input.span.extracting(secondSplit..<input.count))

        var actual = ContiguousArray<UInt8>(
          repeating: 0,
          count: SHA3_256.digestByteCount
        )
        var actualOutput = actual.mutableSpan
        core.finalize(into: &actualOutput)
        XCTAssertEqual(actual, expected)
      }
    }

    var byteCore = KeccakCore(rateByteCount: 136, domainSeparator: 0x06)
    for byte in input {
      try byteCore.update(byte: byte)
    }
    var byteActual = ContiguousArray<UInt8>(
      repeating: 0,
      count: SHA3_256.digestByteCount
    )
    var byteOutput = byteActual.mutableSpan
    byteCore.finalize(into: &byteOutput)
    XCTAssertEqual(byteActual, expected)
  }

  private func copy(_ span: Span<UInt8>) -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private func bytes(_ value: String) -> [UInt8] {
    var result: [UInt8] = []
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }
}
