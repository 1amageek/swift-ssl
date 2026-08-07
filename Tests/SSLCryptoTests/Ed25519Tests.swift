import SSLCore
import XCTest

@_spi(PureSwiftCrypto) @testable import SSLCrypto

final class Ed25519Tests: XCTestCase {
  func testRFC8032SigningVector() throws {
    let seed = bytes(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let expectedPublicKey = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    let expectedSignature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let privateKey = try Ed25519PrivateKey(seed: seed.span)
    let publicKey = try privateKey.publicKey()
    let signature = try privateKey.sign(message: ContiguousArray<UInt8>().span)

    XCTAssertEqual(publicKey, expectedPublicKey)
    XCTAssertEqual(signature, expectedSignature)
  }

  func testRFC8032EmptyMessageVector() throws {
    let publicKey = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    let signature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let key = try Ed25519PublicKey(bytes: publicKey.span)
    let valid = try Ed25519.verify(
      signature: signature.span,
      message: ContiguousArray<UInt8>().span,
      using: key
    )

    XCTAssertTrue(valid)
  }

  func testModifiedMessageDoesNotVerify() throws {
    let publicKey = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    let signature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let message = ContiguousArray<UInt8>([0])
    let key = try Ed25519PublicKey(bytes: publicKey.span)

    let valid = try Ed25519.verify(
      signature: signature.span,
      message: message.span,
      using: key
    )

    XCTAssertFalse(valid)
  }

  func testNonCanonicalScalarIsRejected() throws {
    let publicKey = bytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    var signature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    signature.replaceSubrange(
      32..<64,
      with: bytes(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
      ))
    let key = try Ed25519PublicKey(bytes: publicKey.span)

    do {
      let unused = try Ed25519.verify(
        signature: signature.span,
        message: ContiguousArray<UInt8>().span,
        using: key
      )
      _ = unused
      XCTFail("non-canonical scalar was accepted")
    } catch {
      XCTAssertEqual(error, .nonCanonicalEncoding)
    }
  }

  func testFixedBaseMatchesGenericScalarMultiplication() {
    var generator = DeterministicByteGenerator(state: 0x9e37_79b9_7f4a_7c15)
    for _ in 0..<32 {
      let scalar = referenceReduce(generator.bytes(count: 64))
      XCTAssertEqual(
        Ed25519.scalarMultiplyBaseForTesting(scalar.span),
        Ed25519.scalarMultiplyGenericBaseForTesting(scalar.span)
      )
      XCTAssertEqual(
        Ed25519.scalarMultiplyPublicBaseForTesting(scalar.span),
        Ed25519.scalarMultiplyGenericBaseForTesting(scalar.span)
      )
    }
  }

  func testDoubleScalarMultiplicationMatchesReferencePath() {
    var generator = DeterministicByteGenerator(state: 0x243f_6a88_85a3_08d3)
    for _ in 0..<32 {
      let baseScalar = referenceReduce(generator.bytes(count: 64))
      let pointScalar = referenceReduce(generator.bytes(count: 64))
      XCTAssertEqual(
        Ed25519.doubleScalarMultiplyBaseForTesting(
          baseScalar.span,
          subtracting: pointScalar.span
        ),
        Ed25519.referenceDoubleScalarMultiplyBaseForTesting(
          baseScalar.span,
          subtracting: pointScalar.span
        )
      )
    }
  }

  func testSigningWithPrecomputedPublicKeyMatchesRFC8032() throws {
    let seed = bytes(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let expectedSignature = bytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    let privateKey = try Ed25519PrivateKey(seed: seed.span)
    let publicKey = try privateKey.publicKey()

    let signature = try privateKey.sign(
      message: ContiguousArray<UInt8>().span,
      precomputedPublicKey: publicKey.span
    )

    XCTAssertEqual(signature, expectedSignature)
  }

  func testScalarReductionMatchesReferenceImplementation() {
    var generator = DeterministicByteGenerator(state: 0xd1b5_4a32_d192_ed03)
    for byteCount in [32, 64, 96] {
      for _ in 0..<32 {
        let input = generator.bytes(count: byteCount)
        XCTAssertEqual(
          Ed25519.reduceScalarForTesting(input.span),
          referenceReduce(input)
        )
      }
    }
  }

  func testScalarMultiplicationMatchesReferenceImplementation() {
    var generator = DeterministicByteGenerator(state: 0x94d0_49bb_1331_11eb)
    for _ in 0..<32 {
      let lhs = referenceReduce(generator.bytes(count: 64))
      let rhs = referenceReduce(generator.bytes(count: 64))
      XCTAssertEqual(
        Ed25519.multiplyScalarsForTesting(lhs.span, rhs.span),
        referenceMultiply(lhs, rhs)
      )
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

  private func referenceReduce(_ input: ContiguousArray<UInt8>) -> ContiguousArray<UInt8> {
    let modulus = bytes(
      "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
    )
    var remainder = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var bit = input.count * 8 - 1
    while bit >= 0 {
      var carry = (input[bit >> 3] >> UInt8(bit & 7)) & 1
      var index = 0
      while index < remainder.count {
        let nextCarry = remainder[index] >> 7
        remainder[index] = (remainder[index] << 1) | carry
        carry = nextCarry
        index += 1
      }
      if !referenceIsLessThan(remainder, modulus) {
        referenceSubtract(modulus, from: &remainder)
      }
      bit -= 1
    }
    return remainder
  }

  private func referenceMultiply(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    let modulus = bytes(
      "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
    )
    var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var addend = lhs
    var bit = 0
    while bit < 256 {
      if ((rhs[bit >> 3] >> UInt8(bit & 7)) & 1) == 1 {
        referenceAdd(addend, to: &result)
        if !referenceIsLessThan(result, modulus) {
          referenceSubtract(modulus, from: &result)
        }
      }
      let currentAddend = addend
      referenceAdd(currentAddend, to: &addend)
      if !referenceIsLessThan(addend, modulus) {
        referenceSubtract(modulus, from: &addend)
      }
      bit += 1
    }
    return result
  }

  private func referenceAdd(
    _ addend: ContiguousArray<UInt8>,
    to value: inout ContiguousArray<UInt8>
  ) {
    var carry: UInt16 = 0
    var index = 0
    while index < value.count {
      let sum = UInt16(value[index]) + UInt16(addend[index]) + carry
      value[index] = UInt8(truncatingIfNeeded: sum)
      carry = sum >> 8
      index += 1
    }
    XCTAssertEqual(carry, 0)
  }

  private func referenceSubtract(
    _ subtrahend: ContiguousArray<UInt8>,
    from value: inout ContiguousArray<UInt8>
  ) {
    var borrow: Int16 = 0
    var index = 0
    while index < value.count {
      let difference = Int16(value[index]) - Int16(subtrahend[index]) - borrow
      value[index] = UInt8(truncatingIfNeeded: difference)
      borrow = difference < 0 ? 1 : 0
      index += 1
    }
    XCTAssertEqual(borrow, 0)
  }

  private func referenceIsLessThan(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: ContiguousArray<UInt8>
  ) -> Bool {
    var index = lhs.count - 1
    while index >= 0 {
      if lhs[index] != rhs[index] {
        return lhs[index] < rhs[index]
      }
      index -= 1
    }
    return false
  }

}

private struct DeterministicByteGenerator {
  private var state: UInt64

  init(state: UInt64) {
    self.state = state
  }

  mutating func bytes(count: Int) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(count)
    while output.count < count {
      state ^= state >> 12
      state ^= state << 25
      state ^= state >> 27
      var word = state &* 0x2545_f491_4f6c_dd1d
      var index = 0
      while index < 8 && output.count < count {
        output.append(UInt8(truncatingIfNeeded: word))
        word >>= 8
        index += 1
      }
    }
    return output
  }
}
