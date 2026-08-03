import SSLCore
import XCTest

@testable import SSLCrypto

final class X25519Tests: XCTestCase {
  func testKeyGenerationUsesExplicitEntropySource() throws {
    let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let source = FixedEntropy(bytes: privateBytes)
    let privateKey = try X25519PrivateKey.generate(using: source)

    XCTAssertEqual(
      copyBytes(privateKey.publicKey().span),
      Array(
        bytes(
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )))
  }

  func testRFC7748AlicePublicKey() throws {
    let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let expectedPublic = bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    let privateKey = try X25519PrivateKey(bytes: privateBytes.span)

    let publicKey = privateKey.publicKey()
    XCTAssertEqual(copyBytes(publicKey.span), Array(expectedPublic))
  }

  func testRFC7748ThousandIterationVector() throws {
    var scalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var point = ContiguousArray<UInt8>(repeating: 0, count: 32)
    scalar[0] = 9
    point[0] = 9

    for _ in 0..<1_000 {
      let privateKey = try X25519PrivateKey(bytes: scalar.span)
      let publicKey = try X25519PublicKey(bytes: point.span)
      let sharedSecret = try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKey: publicKey
      )
      point = scalar
      scalar = sharedSecret.withBorrowedBytes { ContiguousArray(copyBytes($0)) }
    }

    XCTAssertEqual(
      Array(scalar),
      Array(bytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))
    )
  }

  func testSharedSecretMatchesIndependentImplementationVector() throws {
    let alicePrivate = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let bobPrivate = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let expected = bytes("5bf220d670c94b8d70bc5ede1cffb85d6c4b7c9d8717bbb5eb90c02583862007")

    let alice = try X25519PrivateKey(bytes: alicePrivate.span)
    let bob = try X25519PrivateKey(bytes: bobPrivate.span)
    let shared = try X25519.sharedSecret(privateKey: alice, peerPublicKey: bob.publicKey())
    let actual = shared.withBorrowedBytes { copyBytes($0) }

    XCTAssertEqual(actual, Array(expected))
  }

  func testDeterministicFieldVectors() throws {
    let vectors = [
      (
        "071a2d405366798c9fb2c5d8ebfe1124374a5d708396a9bccfe2f5081b2e4154",
        "032241607f9ebddcfb1a39587796b5d4f31231506f8eadcceb0a29486786a5c4",
        "58d384f9f6b902c06240510fdf10381db63fe85aa32242a35bf975b5e1ecf03d",
        "dd2ca84fb07a5772486d7a1bf155a1b0063817b6c95f5c59b0d6f2508f071464"
      ),
      (
        "2c3f5265788b9eb1c4d7eafd102336495c6f8295a8bbcee1f4071a2d40536679",
        "0e2d4c6b8aa9c8e70625446382a1c0dffe1d3c5b7a99b8d7f61534537291b0cf",
        "5e0218a005e76a0348e99aac665ebbfcb8eb2ba185079c3c8cab5ccb6cb9cb7a",
        "238d0222c48417aabb07e53ffd411f8bc310802c16858fd1fd070491f3bba562"
      ),
      (
        "5164778a9db0c3d6e9fc0f2235485b6e8194a7bacde0f306192c3f5265788b9e",
        "1938577695b4d3f211304f6e8daccbea0928476685a4c3e201203f5e7d9cbbda",
        "fd134960e08c49fddbc1eb5f793d34c86384eb0e2bfb411309e89ce0ccbca158",
        "dfb60cfd3cea9499c2d0c549996773dfe385e0e6bb73c4fc9fbd521e2e003227"
      ),
      (
        "76899cafc2d5e8fb0e2134475a6d8093a6b9ccdff205182b3e5164778a9db0c3",
        "24436281a0bfdefd1c3b5a7998b7d6f51433527190afceed0c2b4a6988a7c6e5",
        "ed80eabffad44b099c3c9c62d76b1ba3d78b9742c6122060e3f51ecda400a476",
        "5a34659400af7b6267bc4d4b0fa17b38bb41f37eb83a1edc5989af30f452154e"
      ),
    ]

    for (aliceHex, bobHex, publicHex, sharedHex) in vectors {
      let aliceBytes = bytes(aliceHex)
      let bobBytes = bytes(bobHex)
      let alice = try X25519PrivateKey(bytes: aliceBytes.span)
      let bob = try X25519PrivateKey(bytes: bobBytes.span)

      XCTAssertEqual(copyBytes(alice.publicKey().span), Array(bytes(publicHex)))
      let shared = try X25519.sharedSecret(privateKey: alice, peerPublicKey: bob.publicKey())
      XCTAssertEqual(shared.withBorrowedBytes { copyBytes($0) }, Array(bytes(sharedHex)))
    }
  }

  func testAllZeroPeerKeyIsRejectedWithoutReturningSecret() throws {
    let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let zeroPeer = ContiguousArray<UInt8>(repeating: 0, count: X25519PublicKey.byteCount)
    let privateKey = try X25519PrivateKey(bytes: privateBytes.span)
    let peer = try X25519PublicKey(bytes: zeroPeer.span)

    do {
      let unused = try X25519.sharedSecret(privateKey: privateKey, peerPublicKey: peer)
      _ = unused
      XCTFail("all-zero peer key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPeerKey)
    }
  }

  func testAllZeroPeerKeyDoesNotModifyInPlaceOutput() throws {
    let privateBytes = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let zeroPeer = ContiguousArray<UInt8>(repeating: 0, count: X25519PublicKey.byteCount)
    let privateKey = try X25519PrivateKey(bytes: privateBytes.span)
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: X25519SharedSecret.byteCount)
    let original = output

    do {
      var destination = output.mutableSpan
      try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKeyBytes: zeroPeer.span,
        into: &destination
      )
      XCTFail("all-zero peer key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPeerKey)
    }
    XCTAssertEqual(output, original)
  }

  func testInPlacePublicKeyMatchesOwnedPublicKey() throws {
    let privateKey = try X25519PrivateKey(
      bytes: bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").span
    )
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: X25519PublicKey.byteCount
    )
    var destination = output.mutableSpan
    try privateKey.publicKey(into: &destination)

    XCTAssertEqual(Array(output), copyBytes(privateKey.publicKey().span))
  }

  func testEncodedPeerInPlaceAgreementMatchesOwnedResult() throws {
    let alice = try X25519PrivateKey(
      bytes: bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").span
    )
    let bob = try X25519PrivateKey(
      bytes: bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").span
    )
    let bobPublicKey = bob.publicKey()
    let owned = try X25519.sharedSecret(
      privateKey: alice,
      peerPublicKey: bobPublicKey
    )
    var output = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: X25519SharedSecret.byteCount
    )
    var destination = output.mutableSpan
    try X25519.sharedSecret(
      privateKey: alice,
      peerPublicKeyBytes: bobPublicKey.span,
      into: &destination
    )

    XCTAssertEqual(Array(output), owned.withBorrowedBytes { copyBytes($0) })
  }

  func testInPlaceLengthFailuresDoNotModifyOutput() throws {
    let privateKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x42, count: 32).span
    )
    let shortPeer = ContiguousArray<UInt8>(repeating: 0x24, count: 31)
    var output = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
    let original = output
    do {
      var destination = output.mutableSpan
      try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKeyBytes: shortPeer.span,
        into: &destination
      )
      XCTFail("encoded-key agreement accepted a short peer key")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
    }
    XCTAssertEqual(output, original)

    var shortPublicOutput = ContiguousArray<UInt8>(repeating: 0x5A, count: 31)
    let originalPublicOutput = shortPublicOutput
    do {
      var destination = shortPublicOutput.mutableSpan
      try privateKey.publicKey(into: &destination)
      XCTFail("public-key derivation accepted a short output")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
    }
    XCTAssertEqual(shortPublicOutput, originalPublicOutput)
  }

  func testKeyLengthValidation() {
    let invalid = ContiguousArray<UInt8>(repeating: 0, count: 31)
    do {
      let unused = try X25519PrivateKey(bytes: invalid.span)
      _ = unused
      XCTFail("invalid private-key length was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
    }
    do {
      let unused = try X25519PublicKey(bytes: invalid.span)
      _ = unused
      XCTFail("invalid public-key length was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
    }
  }

  private func copyBytes(_ bytes: Span<UInt8>) -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
      result.append(bytes[index])
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
}
