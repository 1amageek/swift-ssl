import SSLCore
import XCTest

@testable import SSLCrypto

final class MLDSA65Tests: XCTestCase {
  func testKeyGenerationMatchesNISTACVPFIPS204() throws {
    let pair = try MLDSA65.keyPair(
      seed: bytes("70CEFB9AED5B68E018B079DA8284B9D5CAD5499ED9C265FF73588005D85C225C").span
    )

    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("646B26B8D09DBC9E865B6A006C693A3127B065E62FAB5FBE8B159C416462FEB6")
    )
    let representation = try pair.privateKey.standardRepresentation()
    let privateDigest = try representation.withBorrowedBytes { input throws in
      try digest(input)
    }
    XCTAssertEqual(
      privateDigest,
      bytes("3894DC56A4553781D68FF0D1B6FCF1B4876085EA602FB6F8738DEF50ED7D4C75")
    )
  }

  func testDeterministicSignatureRoundTripAndDomainSeparation() throws {
    let pair = try keyPair()
    let message = ContiguousArray("swift-ssl ML-DSA-65".utf8)
    let context = ContiguousArray("tls-certificate-verify".utf8)
    let randomizer = ContiguousArray<UInt8>(repeating: 0, count: MLDSA65.randomizerByteCount)
    let signature = try MLDSA65.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      randomizer: randomizer.span
    )

    XCTAssertTrue(
      try MLDSA65.verify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )

    var modifiedMessage = message
    modifiedMessage[0] ^= 1
    XCTAssertFalse(
      try MLDSA65.verify(
        signature: signature.span,
        message: modifiedMessage.span,
        context: context.span,
        using: pair.publicKey
      )
    )

    let otherContext = ContiguousArray("different-context".utf8)
    XCTAssertFalse(
      try MLDSA65.verify(
        signature: signature.span,
        message: message.span,
        context: otherContext.span,
        using: pair.publicKey
      )
    )

    var modifiedSignature = signature
    modifiedSignature[0] ^= 1
    XCTAssertFalse(
      try MLDSA65.verify(
        signature: modifiedSignature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
  }

  func testSeededSignatureMatchesWycheproof() throws {
    let seed = ContiguousArray<UInt8>(repeating: 0x2A, count: MLDSA65.seedByteCount)
    let pair = try MLDSA65.keyPair(seed: seed.span)
    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("B7ACCE2DDB11F8CC1AA46E2BAFAC6EACFA2B732EF192BD636AD8D3A56D649C66")
    )

    let message = ContiguousArray("Hello world".utf8)
    let context = ContiguousArray<UInt8>()
    let randomizer = ContiguousArray<UInt8>(repeating: 0, count: MLDSA65.randomizerByteCount)
    let signature = try MLDSA65.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      randomizer: randomizer.span
    )

    XCTAssertEqual(
      try digest(signature.span),
      bytes("39FBBB0D97A52C79844213B325AF823A7F16A174E00A5B3DAEB3E6E6D1C89681")
    )
    XCTAssertTrue(
      try MLDSA65.verify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
  }

  func testRandomizedSigningProducesDistinctValidSignatures() throws {
    let pair = try keyPair()
    let message = ContiguousArray("randomized signature".utf8)
    let context = ContiguousArray<UInt8>()
    let first = try MLDSA65.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      entropy: FixedEntropy(byte: 0x31)
    )
    let second = try MLDSA65.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      entropy: FixedEntropy(byte: 0x72)
    )

    XCTAssertNotEqual(first, second)
    XCTAssertTrue(
      try MLDSA65.verify(
        signature: first.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
    XCTAssertTrue(
      try MLDSA65.verify(
        signature: second.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
  }

  func testPrivateKeyImportRejectsCorruption() throws {
    let pair = try keyPair()
    let representation = try pair.privateKey.standardRepresentation()
    var encoded = representation.withBorrowedBytes { copy($0) }
    encoded[100] ^= 1

    do {
      let unused = try MLDSA65PrivateKey(encoded: encoded.span)
      _ = consume unused
      XCTFail("corrupt ML-DSA private key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }
  }

  func testPrivateKeyImportRejectsNonCanonicalShortEncoding() throws {
    let pair = try keyPair()
    let representation = try pair.privateKey.standardRepresentation()
    var encoded = representation.withBorrowedBytes { copy($0) }
    encoded[128] = 0xFF

    do {
      let unused = try MLDSA65PrivateKey(encoded: encoded.span)
      _ = consume unused
      XCTFail("noncanonical ML-DSA short-vector encoding was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }
  }

  func testInPlaceEntropyFailureLeavesOutputUnchanged() throws {
    let pair = try keyPair()
    let message = ContiguousArray("failure atomicity".utf8)
    let context = ContiguousArray<UInt8>()
    var signature = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLDSA65.signatureByteCount
    )
    let original = signature

    do {
      var output = signature.mutableSpan
      try MLDSA65.sign(
        message: message.span,
        context: context.span,
        using: pair.privateKey,
        entropy: FailingEntropy(),
        into: &output
      )
      XCTFail("ML-DSA signing accepted an entropy failure")
    } catch {
      XCTAssertEqual(error, .entropy(.sourceRejected))
    }
    XCTAssertEqual(signature, original)
  }

  func testInputLengthsAreValidated() throws {
    let shortSeed = ContiguousArray<UInt8>(repeating: 0, count: MLDSA65.seedByteCount - 1)
    do {
      let unused = try MLDSA65.keyPair(seed: shortSeed.span)
      _ = consume unused
      XCTFail("short ML-DSA seed was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .invalidSeedLength(expected: MLDSA65.seedByteCount, actual: shortSeed.count)
      )
    }

    let pair = try keyPair()
    let oversizedContext = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLDSA65.maximumContextByteCount + 1
    )
    XCTAssertThrowsError(
      try MLDSA65.sign(
        message: ContiguousArray<UInt8>().span,
        context: oversizedContext.span,
        using: pair.privateKey,
        entropy: FixedEntropy(byte: 0)
      )
    ) { error in
      XCTAssertEqual(
        error as? MLDSAError,
        .contextTooLong(
          limit: MLDSA65.maximumContextByteCount,
          actual: oversizedContext.count
        )
      )
    }
  }

  private func keyPair() throws -> MLDSA65KeyPair {
    try MLDSA65.keyPair(
      seed: bytes("70CEFB9AED5B68E018B079DA8284B9D5CAD5499ED9C265FF73588005D85C225C").span
    )
  }

  private struct FixedEntropy: EntropySource {
    let byte: UInt8

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
    }
  }

  private struct FailingEntropy: EntropySource {
    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      if !destination.isEmpty {
        destination[0] = 0xC3
      }
      throw .sourceRejected
    }
  }

  private func digest(_ input: Span<UInt8>) throws -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
    var destination = output.mutableSpan
    try SHA256.hash(input, into: &destination)
    return output
  }

  private func copy(_ input: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(input.count)
    var index = 0
    while index < input.count {
      result.append(input[index])
      index += 1
    }
    return result
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
