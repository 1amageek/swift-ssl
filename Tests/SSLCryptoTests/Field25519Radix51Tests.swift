import SSLCore
import XCTest

@testable import SSLCrypto

final class Field25519Radix51Tests: XCTestCase {
  func testEd25519VerificationDigestStreamingFixture() throws {
    let encodedR = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    )
    let publicKey = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    var context = SHA512.makeContext()
    try context.update(encodedR.span)
    try context.update(publicKey.span)
    try context.update(ContiguousArray<UInt8>().span)
    var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
    var output = digest.mutableSpan
    try context.finalize(into: &output)

    XCTAssertEqual(
      digest,
      bytes(
        "2771062b6b536fe7ffbdda0320c3827b035df10d284df3f08222f04dbca7a4c2"
          + "0ef15bdc988a22c7207411377c33f2ac09b1e86a046234283768ee7ba03c0e9f"
      )
    )
  }

  func testEd25519SignatureRSquareRootFixture() {
    let signature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let yBytes = ContiguousArray(signature[0..<32])
    XCTAssertNoThrow(try Ed25519PublicKey(bytes: yBytes.span))
    XCTAssertNoThrow(try Ed25519PublicKey(bytes: signature.span.extracting(0..<32)))
    let y = Field25519(bytes: yBytes.span)
    XCTAssertEqual(y.bytes, yBytes)

    let ySquared = y * y
    let u = ySquared - Field25519(constant: 1)
    let v = Field25519.edwardsD * ySquared + Field25519(constant: 1)
    XCTAssertEqual(
      u.bytes,
      bytes("f86692466d9de0817fc4f8a9b84d3b35e26eee7076b9053e2fad4260cfbf1758")
    )
    XCTAssertEqual(
      v.bytes,
      bytes("b452e59ae0e6a006cb8e33864cc8d19f0c5881a643675caba6ba1c2162acc65e")
    )

    let v2 = v * v
    let v3 = v2 * v
    let v7 = v3 * v3 * v
    let exponent = u * v7
    var result = Field25519(one: true)
    var bit = 251
    while bit >= 0 {
      result = result * result
      if bit >= 2 || bit == 0 {
        result = result * exponent
      }
      bit -= 1
    }
    let candidate = u * v3 * result
    XCTAssertEqual(
      candidate.bytes,
      bytes("2ac85929e644ab81cff3e61cd04b32827183467f12b338c3fc6500d409e31862")
    )
    XCTAssertEqual((candidate * candidate * v).bytes, u.bytes)
  }

  func testEd25519SquareRootFixture() {
    let yBytes = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    XCTAssertNoThrow(try Ed25519PublicKey(bytes: yBytes.span))
    let y = Field25519(bytes: yBytes.span)
    let ySquared = y * y
    let u = ySquared - Field25519(constant: 1)
    let v = Field25519.edwardsD * ySquared + Field25519(constant: 1)

    XCTAssertEqual(
      u.bytes,
      bytes("cb74f50f73b58c471c345f4746bf62670c5d4b7856c1b69a6314db4732540d3f")
    )
    XCTAssertEqual(
      v.bytes,
      bytes("e4bb1ba3cf1bfc5cb80430abb6551331555a82d0601ebc115c2b469f9cc81b77")
    )

    let v2 = v * v
    let v3 = v2 * v
    let v7 = v3 * v3 * v
    let exponent = u * v7
    var result = Field25519(one: true)
    var bit = 251
    while bit >= 0 {
      result = result * result
      if bit >= 2 || bit == 0 {
        result = result * exponent
      }
      bit -= 1
    }
    let candidate = u * v3 * result
    XCTAssertEqual(
      candidate.bytes,
      bytes("40c7570f4dd54835b9131184410ed4a0cc93e7d9ad053cbc6d07a62426999502")
    )
    XCTAssertEqual(
      (candidate * candidate * v).bytes,
      bytes("228b0af08c4a73b8e3cba0b8b9409d98f3a2b487a93e49659ceb24b8cdabf240")
    )
    XCTAssertEqual((candidate * candidate * v).bytes, (-u).bytes)
    let corrected = candidate * Field25519.edwardsSqrtM1
    XCTAssertEqual(
      corrected.bytes,
      bytes("1fba89884279d84edb83e7ac8d2bec3adf092f9f721f68ddd6cb62d4651f2f2a")
    )
    XCTAssertEqual((corrected * corrected * v).bytes, u.bytes)
    XCTAssertNoThrow(try Ed25519PublicKey(bytes: yBytes.span))
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
