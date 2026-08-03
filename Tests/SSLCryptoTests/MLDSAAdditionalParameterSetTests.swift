import SSLCore
import XCTest

@testable import SSLCrypto

final class MLDSAAdditionalParameterSetTests: XCTestCase {
  func testMLDSA44KeyGenerationMatchesNISTACVPFIPS204() throws {
    let pair = try MLDSA44.keyPair(
      seed: bytes("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B").span
    )

    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("451A808C522218FADBDAB146FC12004B0741C7D069F238F43AD77216159F6A34")
    )
    let representation = try pair.privateKey.standardRepresentation()
    let privateDigest = try representation.withBorrowedBytes { input throws in
      try digest(input)
    }
    XCTAssertEqual(
      privateDigest,
      bytes("0196CCBDE5FBD1804E8C784EFB83998338076D586FE73EE07BA712CCC9FC32C2")
    )
  }

  func testMLDSA44SeededSignatureMatchesWycheproof() throws {
    let seed = ContiguousArray<UInt8>(repeating: 0x2A, count: MLDSA44.seedByteCount)
    let pair = try MLDSA44.keyPair(seed: seed.span)
    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("D87F8CA136AC1AA55E2D6C4521680EFB3A378CBB9BC0BFB446E9C60893931EA3")
    )

    let message = ContiguousArray("Hello world".utf8)
    let context = ContiguousArray<UInt8>()
    let randomizer = ContiguousArray<UInt8>(repeating: 0, count: MLDSA44.randomizerByteCount)
    let signature = try MLDSA44.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      randomizer: randomizer.span
    )

    XCTAssertEqual(
      try digest(signature.span),
      bytes("8CD6FC03DAA72E87210A4E721523E84C14F27733789075E65736744D4787FDD5")
    )
    XCTAssertTrue(
      try MLDSA44.verify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )

    var modifiedSignature = signature
    modifiedSignature[0] ^= 1
    XCTAssertFalse(
      try MLDSA44.verify(
        signature: modifiedSignature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
  }

  func testMLDSA44RejectsInvalidPrivateKeyAndInputLengths() throws {
    let pair = try MLDSA44.keyPair(
      seed: ContiguousArray<UInt8>(repeating: 0x44, count: MLDSA44.seedByteCount).span
    )
    let representation = try pair.privateKey.standardRepresentation()
    var corrupt = representation.withBorrowedBytes { copy($0) }
    corrupt[100] ^= 1
    do {
      let unused = try MLDSA44PrivateKey(encoded: corrupt.span)
      _ = consume unused
      XCTFail("corrupt ML-DSA-44 private key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }

    var noncanonical = representation.withBorrowedBytes { copy($0) }
    noncanonical[128] = 0xFF
    do {
      let unused = try MLDSA44PrivateKey(encoded: noncanonical.span)
      _ = consume unused
      XCTFail("noncanonical ML-DSA-44 short-vector encoding was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }

    let shortSeed = ContiguousArray<UInt8>(repeating: 0, count: MLDSA44.seedByteCount - 1)
    do {
      let unused = try MLDSA44.keyPair(seed: shortSeed.span)
      _ = consume unused
      XCTFail("short ML-DSA-44 seed was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .invalidSeedLength(expected: MLDSA44.seedByteCount, actual: shortSeed.count)
      )
    }
  }

  func testMLDSA44EntropyFailureLeavesOutputUnchanged() throws {
    let pair = try MLDSA44.keyPair(
      seed: ContiguousArray<UInt8>(repeating: 0x44, count: MLDSA44.seedByteCount).span
    )
    var signature = ContiguousArray<UInt8>(repeating: 0xA5, count: MLDSA44.signatureByteCount)
    let original = signature
    do {
      var output = signature.mutableSpan
      try MLDSA44.sign(
        message: ContiguousArray("failure atomicity".utf8).span,
        context: ContiguousArray<UInt8>().span,
        using: pair.privateKey,
        entropy: FailingEntropy(),
        into: &output
      )
      XCTFail("ML-DSA-44 signing accepted an entropy failure")
    } catch {
      XCTAssertEqual(error, .entropy(.sourceRejected))
    }
    XCTAssertEqual(signature, original)
  }

  func testMLDSA87KeyGenerationMatchesNISTACVPFIPS204() throws {
    let pair = try MLDSA87.keyPair(
      seed: bytes("19E9E5EFE0C1549DDB1D72213636D16FE2FAEB2428257004AE464094CA536A66").span
    )

    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("829D88FD913CCA728FF6B19BCE6CED5E73A54347411DB3A4A75F563F18C1CE65")
    )
    let representation = try pair.privateKey.standardRepresentation()
    let privateDigest = try representation.withBorrowedBytes { input throws in
      try digest(input)
    }
    XCTAssertEqual(
      privateDigest,
      bytes("740343B50C884D5DC4026E7A9CD9C4F17CD41AA4BDA5CCDDFF0C9BB8A920836C")
    )
  }

  func testMLDSA87SeededSignatureMatchesWycheproof() throws {
    let seed = ContiguousArray<UInt8>(repeating: 0x2A, count: MLDSA87.seedByteCount)
    let pair = try MLDSA87.keyPair(seed: seed.span)
    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("D43128FA8A8C785C1D44C9E7DB538DBF9DD88FE6C8AD911A344BCEC1017C6D54")
    )

    let message = ContiguousArray("Hello world".utf8)
    let context = ContiguousArray<UInt8>()
    let randomizer = ContiguousArray<UInt8>(repeating: 0, count: MLDSA87.randomizerByteCount)
    let signature = try MLDSA87.sign(
      message: message.span,
      context: context.span,
      using: pair.privateKey,
      randomizer: randomizer.span
    )

    XCTAssertEqual(
      try digest(signature.span),
      bytes("1AD45BD0419E694375BD38EC11D8E0C228AB9FFAC2FCE4ADBE6218D9C949E293")
    )
    XCTAssertTrue(
      try MLDSA87.verify(
        signature: signature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )

    var modifiedSignature = signature
    modifiedSignature[0] ^= 1
    XCTAssertFalse(
      try MLDSA87.verify(
        signature: modifiedSignature.span,
        message: message.span,
        context: context.span,
        using: pair.publicKey
      )
    )
  }

  func testMLDSA87RejectsInvalidPrivateKeyAndInputLengths() throws {
    let pair = try MLDSA87.keyPair(
      seed: ContiguousArray<UInt8>(repeating: 0x87, count: MLDSA87.seedByteCount).span
    )
    let representation = try pair.privateKey.standardRepresentation()
    var corrupt = representation.withBorrowedBytes { copy($0) }
    corrupt[100] ^= 1
    do {
      let unused = try MLDSA87PrivateKey(encoded: corrupt.span)
      _ = consume unused
      XCTFail("corrupt ML-DSA-87 private key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }

    var noncanonical = representation.withBorrowedBytes { copy($0) }
    noncanonical[128] = 0xFF
    do {
      let unused = try MLDSA87PrivateKey(encoded: noncanonical.span)
      _ = consume unused
      XCTFail("noncanonical ML-DSA-87 short-vector encoding was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }

    let shortSeed = ContiguousArray<UInt8>(repeating: 0, count: MLDSA87.seedByteCount - 1)
    do {
      let unused = try MLDSA87.keyPair(seed: shortSeed.span)
      _ = consume unused
      XCTFail("short ML-DSA-87 seed was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .invalidSeedLength(expected: MLDSA87.seedByteCount, actual: shortSeed.count)
      )
    }
  }

  func testMLDSA87EntropyFailureLeavesOutputUnchanged() throws {
    let pair = try MLDSA87.keyPair(
      seed: ContiguousArray<UInt8>(repeating: 0x87, count: MLDSA87.seedByteCount).span
    )
    var signature = ContiguousArray<UInt8>(repeating: 0xA5, count: MLDSA87.signatureByteCount)
    let original = signature
    do {
      var output = signature.mutableSpan
      try MLDSA87.sign(
        message: ContiguousArray("failure atomicity".utf8).span,
        context: ContiguousArray<UInt8>().span,
        using: pair.privateKey,
        entropy: FailingEntropy(),
        into: &output
      )
      XCTFail("ML-DSA-87 signing accepted an entropy failure")
    } catch {
      XCTAssertEqual(error, .entropy(.sourceRejected))
    }
    XCTAssertEqual(signature, original)
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
