import SwiftSSLCore

/// Verification-only P-256 ECDSA over a caller-provided message digest.
///
/// The public key, digest, and signature are public verification inputs, so
/// this implementation does not carry a secret-dependent timing contract.
/// The raw signature format is fixed-width `r || s`; DER decoding belongs to
/// the X.509/ASN.1 layer.
public enum P256ECDSA: DigestSignatureVerifier {
  public typealias PublicKey = P256PublicKey

  public static let signatureByteCount = 64

  /// Verifies a raw ECDSA signature encoded as fixed-width `r || s`.
  ///
  /// The digest is interpreted as a big-endian integer and truncated to the
  /// curve order width, as specified by SEC 1. The caller is responsible for
  /// selecting the digest algorithm named by the surrounding protocol.
  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing P256PublicKey
  ) throws(CryptoInputError) -> Bool {
    guard signature.count == Self.signatureByteCount else {
      throw .invalidLength(expected: Self.signatureByteCount, actual: signature.count)
    }
    guard messageHash.count >= 32 else {
      throw .invalidLength(expected: 32, actual: messageHash.count)
    }

    let r = P256Scalar(bytes: signature.extracting(0..<32))
    let s = P256Scalar(bytes: signature.extracting(32..<64))
    guard !r.isZero, !s.isZero, r < .order, s < .order else {
      throw .nonCanonicalEncoding
    }

    let digest = P256Scalar(bytes: messageHash.extracting(0..<32)).reduced
    let inverse = s.inverted()
    let u1 = digest * inverse
    let u2 = r * inverse

    let point: P256Point
    do {
      point = try publicKey.withBorrowedPoint { publicPoint throws(CryptoInputError) in
        let first = P256Point.scalarMultiply(P256Point.generator, scalar: u1.encoded.span)
        let second = P256Point.scalarMultiply(publicPoint, scalar: u2.encoded.span)
        return first.adding(second)
      }
    } catch {
      throw .invalidPeerKey
    }
    guard let affine = point.affine() else { return false }
    return P256Scalar(words: affine.x.words).reduced == r
  }

}

public struct P256PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount = 65
  private let storage: OwnedBytes
  private let point: P256Point

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.uncompressedByteCount else {
      throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
    }
    guard let point = P256Point.decodeUncompressed(bytes) else {
      throw .invalidPeerKey
    }
    self.storage = OwnedBytes(copying: bytes)
    self.point = point
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(storage.span)
  }

  fileprivate borrowing func withBorrowedPoint<Result: ~Copyable, Failure: Error>(
    _ body: (P256Point) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(point)
  }
}

private struct P256Scalar: Equatable, Comparable {
  static let order = P256Scalar(
    hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
  let words: SIMD8<UInt32>

  init(bytes: Span<UInt8>) {
    self.words = P256Words.decode(bytes)
  }

  init(hex: String) {
    self.words = P256Words.decode(hex: hex)
  }

  init(words: SIMD8<UInt32>) {
    self.words = words
  }

  var isZero: Bool {
    var value: UInt32 = 0
    var index = 0
    while index < 8 {
      value |= words[index]
      index += 1
    }
    return value == 0
  }

  var reduced: P256Scalar {
    P256Words.compare(words, Self.order.words) >= 0
      ? P256Scalar(words: P256Words.subtract(words, Self.order.words))
      : self
  }

  var encoded: ContiguousArray<UInt8> {
    P256Words.encode(words)
  }

  func inverted() -> P256Scalar {
    Self.power(self, exponent: Self.inverseExponent)
  }

  static func + (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    var result = SIMD8<UInt32>(repeating: 0)
    var carry: UInt64 = 0
    var index = 0
    while index < 8 {
      let sum = UInt64(lhs.words[index]) + UInt64(rhs.words[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    if carry != 0 {
      result = P256Words.add(result, Self.modulusComplement)
    } else if P256Words.compare(result, Self.order.words) >= 0 {
      result = P256Words.subtract(result, Self.order.words)
    }
    return P256Scalar(words: result)
  }

  static func - (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    var result = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let minuend = UInt64(lhs.words[index])
      let subtrahend = UInt64(rhs.words[index]) + borrow
      if minuend < subtrahend {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
        borrow = 0
      }
      index += 1
    }
    if borrow != 0 {
      result = P256Words.add(result, Self.order.words)
    }
    return P256Scalar(words: result)
  }

  static func * (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    var product = [UInt64](repeating: 0, count: 16)
    var i = 0
    while i < 8 {
      var carry: UInt64 = 0
      var j = 0
      while j < 8 {
        let value = UInt64(lhs.words[i]) * UInt64(rhs.words[j]) + product[i + j] + carry
        product[i + j] = value & 0xFFFF_FFFF
        carry = value >> 32
        j += 1
      }
      var index = i + 8
      while carry != 0 {
        let value = product[index] + carry
        product[index] = value & 0xFFFF_FFFF
        carry = value >> 32
        index += 1
      }
      i += 1
    }

    var remainder = [UInt64](repeating: 0, count: 9)
    var bit = 511
    while bit >= 0 {
      var carry = (product[bit >> 5] >> UInt64(bit & 31)) & 1
      var index = 0
      while index < 9 {
        let value = (remainder[index] << 1) | carry
        remainder[index] = value & 0xFFFF_FFFF
        carry = value >> 32
        index += 1
      }
      if remainder[8] != 0
        || P256Words.compare(
          P256Words.truncate(remainder), Self.order.words
        ) >= 0
      {
        var borrow: UInt64 = 0
        index = 0
        while index < 8 {
          let minuend = remainder[index]
          let subtrahend = UInt64(Self.order.words[index]) + borrow
          if minuend < subtrahend {
            remainder[index] = (UInt64(1) << 32) + minuend - subtrahend
            borrow = 1
          } else {
            remainder[index] = minuend - subtrahend
            borrow = 0
          }
          index += 1
        }
        remainder[8] -= borrow
      }
      bit -= 1
    }
    return P256Scalar(words: P256Words.truncate(remainder))
  }

  private static let modulusComplement = P256Words.decode(
    hex: "00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF"
  )
  private static let inverseExponent = P256Words.decode(
    hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F"
  )

  private static func power(_ value: P256Scalar, exponent: SIMD8<UInt32>) -> P256Scalar {
    var one = SIMD8<UInt32>(repeating: 0)
    one[0] = 1
    var result = P256Scalar(words: one)
    var bit = 255
    while bit >= 0 {
      result = result * result
      if ((exponent[bit >> 5] >> UInt32(bit & 31)) & 1) == 1 {
        result = result * value
      }
      bit -= 1
    }
    return result
  }

  static func < (lhs: P256Scalar, rhs: P256Scalar) -> Bool {
    var index = 7
    while index >= 0 {
      if lhs.words[index] != rhs.words[index] {
        return lhs.words[index] < rhs.words[index]
      }
      index -= 1
    }
    return false
  }
}

struct P256Field: Equatable {
  static let modulus = SIMD8<UInt32>(
    0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0001, 0xFFFF_FFFF
  )
  private static let modulusComplement = SIMD8<UInt32>(
    0x0000_0001, 0x0000_0000, 0x0000_0000, 0xFFFF_FFFF,
    0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFE, 0x0000_0000
  )
  private static let inverseExponent = SIMD8<UInt32>(
    0xFFFF_FFFD, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0001, 0xFFFF_FFFF
  )
  private static let sqrtExponent = SIMD8<UInt32>(
    0x0000_0000, 0x0000_0000, 0x4000_0000, 0x0000_0000,
    0x0000_0000, 0x4000_0000, 0xC000_0000, 0x3FFF_FFFF
  )

  let words: SIMD8<UInt32>

  init(words: SIMD8<UInt32>) {
    self.words = words
  }

  init(constant: UInt32) {
    var words = SIMD8<UInt32>(repeating: 0)
    words[0] = constant
    self.words = words
  }

  init(hex: String) {
    self.words = P256Words.decode(hex: hex)
  }

  static let zero = P256Field(constant: 0)
  static let one = P256Field(constant: 1)
  static let curveB = P256Field(
    hex: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")

  var isZero: Bool {
    var value: UInt32 = 0
    var index = 0
    while index < 8 {
      value |= words[index]
      index += 1
    }
    return value == 0
  }

  var isCanonical: Bool {
    P256Words.compare(words, Self.modulus) < 0
  }

  var isOdd: Bool { words[0] & 1 == 1 }

  var encoded: ContiguousArray<UInt8> {
    P256Words.encode(words)
  }

  static func + (lhs: P256Field, rhs: P256Field) -> P256Field {
    var result = SIMD8<UInt32>(repeating: 0)
    var carry: UInt64 = 0
    var index = 0
    while index < 8 {
      let sum = UInt64(lhs.words[index]) + UInt64(rhs.words[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    if carry != 0 {
      result = P256Words.add(result, modulusComplement)
    } else if P256Words.compare(result, modulus) >= 0 {
      result = P256Words.subtract(result, modulus)
    }
    return P256Field(words: result)
  }

  static func - (lhs: P256Field, rhs: P256Field) -> P256Field {
    var result = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let minuend = UInt64(lhs.words[index])
      let subtrahend = UInt64(rhs.words[index]) + borrow
      if minuend < subtrahend {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
        borrow = 0
      }
      index += 1
    }
    if borrow != 0 {
      var corrected = SIMD8<UInt32>(repeating: 0)
      var carry: UInt64 = 0
      index = 0
      while index < 8 {
        let sum = UInt64(result[index]) + UInt64(modulus[index]) + carry
        corrected[index] = UInt32(truncatingIfNeeded: sum)
        carry = sum >> 32
        index += 1
      }
      result = corrected
    }
    return P256Field(words: result)
  }

  static prefix func - (value: P256Field) -> P256Field {
    value.isZero ? .zero : P256Field(words: P256Words.subtract(modulus, value.words))
  }

  static func * (lhs: P256Field, rhs: P256Field) -> P256Field {
    var product = [UInt64](repeating: 0, count: 16)
    var i = 0
    while i < 8 {
      var carry: UInt64 = 0
      var j = 0
      while j < 8 {
        let value = UInt64(lhs.words[i]) * UInt64(rhs.words[j]) + product[i + j] + carry
        product[i + j] = value & 0xFFFF_FFFF
        carry = value >> 32
        j += 1
      }
      var index = i + 8
      while carry != 0 {
        let value = product[index] + carry
        product[index] = value & 0xFFFF_FFFF
        carry = value >> 32
        index += 1
      }
      i += 1
    }
    var remainder = [UInt64](repeating: 0, count: 9)
    var bit = 511
    while bit >= 0 {
      var carry = (product[bit >> 5] >> UInt64(bit & 31)) & 1
      var index = 0
      while index < 9 {
        let value = (remainder[index] << 1) | carry
        remainder[index] = value & 0xFFFF_FFFF
        carry = value >> 32
        index += 1
      }
      if remainder[8] != 0
        || P256Words.compare(
          P256Words.truncate(remainder), modulus
        ) >= 0
      {
        var borrow: UInt64 = 0
        index = 0
        while index < 8 {
          let minuend = remainder[index]
          let subtrahend = UInt64(modulus[index]) + borrow
          if minuend < subtrahend {
            remainder[index] = (UInt64(1) << 32) + minuend - subtrahend
            borrow = 1
          } else {
            remainder[index] = minuend - subtrahend
            borrow = 0
          }
          index += 1
        }
        remainder[8] -= borrow
      }
      bit -= 1
    }
    return P256Field(words: P256Words.truncate(remainder))
  }

  func squared() -> P256Field { self * self }

  func inverted() -> P256Field {
    Self.power(self, exponent: Self.inverseExponent)
  }

  func squareRoot() -> P256Field? {
    let candidate = Self.power(self, exponent: Self.sqrtExponent)
    return candidate.squared() == self ? candidate : nil
  }

  private static func power(_ value: P256Field, exponent: SIMD8<UInt32>) -> P256Field {
    var result = P256Field.one
    var bit = 255
    while bit >= 0 {
      result = result.squared()
      if ((exponent[bit >> 5] >> UInt32(bit & 31)) & 1) == 1 {
        result = result * value
      }
      bit -= 1
    }
    return result
  }
}

private struct P256Point: Equatable {
  static let infinity = P256Point(x: .zero, y: .zero, z: .zero)
  static let generator = P256Point(
    x: P256Field(hex: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    y: P256Field(hex: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    z: .one
  )

  let x: P256Field
  let y: P256Field
  let z: P256Field

  var isInfinity: Bool { z.isZero }

  init(x: P256Field, y: P256Field, z: P256Field) {
    self.x = x
    self.y = y
    self.z = z
  }

  static func decodeUncompressed(_ bytes: Span<UInt8>) -> P256Point? {
    guard bytes.count == 65, bytes[0] == 0x04 else { return nil }
    let x = P256Field(words: P256Words.decode(bytes.extracting(1..<33)))
    let y = P256Field(words: P256Words.decode(bytes.extracting(33..<65)))
    guard x.isCanonical, y.isCanonical else { return nil }
    let point = P256Point(x: x, y: y, z: .one)
    return point.isOnCurve ? point : nil
  }

  var isOnCurve: Bool {
    guard !isInfinity else { return false }
    let left = y.squared()
    let right = x.squared() * x - P256Field(constant: 3) * x + P256Field.curveB
    return left == right
  }

  var encodedUncompressed: ContiguousArray<UInt8> {
    guard let affine = affine() else { return [] }
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(65)
    bytes.append(0x04)
    bytes.append(contentsOf: affine.x.encoded)
    bytes.append(contentsOf: affine.y.encoded)
    return bytes
  }

  func affine() -> P256Point? {
    guard !isInfinity else { return nil }
    let inverse = z.inverted()
    let inverseSquared = inverse.squared()
    let affineX = x * inverseSquared
    let affineY = y * inverseSquared * inverse
    return P256Point(x: affineX, y: affineY, z: .one)
  }

  func doubled() -> P256Point {
    guard !isInfinity, !y.isZero else { return .infinity }
    let ySquared = y.squared()
    let s = P256Field(constant: 4) * x * ySquared
    let zSquared = z.squared()
    let m = P256Field(constant: 3) * (x - zSquared) * (x + zSquared)
    let x3 = m.squared() - P256Field(constant: 2) * s
    let y4 = ySquared.squared()
    let y3 = m * (s - x3) - P256Field(constant: 8) * y4
    let z3 = P256Field(constant: 2) * y * z
    return P256Point(x: x3, y: y3, z: z3)
  }

  func adding(_ other: P256Point) -> P256Point {
    guard !isInfinity else { return other }
    guard !other.isInfinity else { return self }
    let z1Squared = z.squared()
    let z2Squared = other.z.squared()
    let u1 = x * z2Squared
    let u2 = other.x * z1Squared
    let s1 = y * other.z * z2Squared
    let s2 = other.y * z * z1Squared
    if u1 == u2 {
      return s1 == s2 ? doubled() : .infinity
    }
    let h = u2 - u1
    let i = (P256Field(constant: 2) * h).squared()
    let j = h * i
    let r = P256Field(constant: 2) * (s2 - s1)
    let v = u1 * i
    let x3 = r.squared() - j - P256Field(constant: 2) * v
    let y3 = r * (v - x3) - P256Field(constant: 2) * s1 * j
    let z3 = ((z + other.z).squared() - z1Squared - z2Squared) * h
    return P256Point(x: x3, y: y3, z: z3)
  }

  static func scalarMultiply(_ point: P256Point, scalar: Span<UInt8>) -> P256Point {
    var result = P256Point.infinity
    var byteIndex = 0
    while byteIndex < scalar.count {
      var bit = 7
      while bit >= 0 {
        result = result.doubled()
        if ((scalar[byteIndex] >> UInt8(bit)) & 1) == 1 {
          result = result.adding(point)
        }
        bit -= 1
      }
      byteIndex += 1
    }
    return result
  }
}

private enum P256Words {
  static func decode(_ bytes: Span<UInt8>) -> SIMD8<UInt32> {
    var words = SIMD8<UInt32>(repeating: 0)
    var word = 0
    while word < 8 {
      let offset = bytes.count - (word + 1) * 4
      words[word] =
        (UInt32(bytes[offset]) << 24)
        | (UInt32(bytes[offset + 1]) << 16)
        | (UInt32(bytes[offset + 2]) << 8)
        | UInt32(bytes[offset + 3])
      word += 1
    }
    return words
  }

  static func decode(hex: String) -> SIMD8<UInt32> {
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(hex.utf8.count / 2)
    var high: UInt8 = 0
    var haveHigh = false
    for character in hex.utf8 {
      let value: UInt8
      switch character {
      case 0x30...0x39: value = character - 0x30
      case 0x41...0x46: value = character - 0x41 + 10
      case 0x61...0x66: value = character - 0x61 + 10
      default: value = 0
      }
      if haveHigh {
        bytes.append((high << 4) | value)
        haveHigh = false
      } else {
        high = value
        haveHigh = true
      }
    }
    return decode(bytes.span)
  }

  static func encode(_ words: SIMD8<UInt32>) -> ContiguousArray<UInt8> {
    var bytes = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var word = 0
    while word < 8 {
      let offset = (7 - word) * 4
      let value = words[word]
      bytes[offset] = UInt8(truncatingIfNeeded: value >> 24)
      bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
      bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
      bytes[offset + 3] = UInt8(truncatingIfNeeded: value)
      word += 1
    }
    return bytes
  }

  static func compare(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> Int {
    var index = 7
    while index >= 0 {
      if lhs[index] != rhs[index] {
        return lhs[index] < rhs[index] ? -1 : 1
      }
      index -= 1
    }
    return 0
  }

  static func subtract(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let minuend = UInt64(lhs[index])
      let subtrahend = UInt64(rhs[index]) + borrow
      if minuend < subtrahend {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
        borrow = 0
      }
      index += 1
    }
    return result
  }

  static func add(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var carry: UInt64 = 0
    var index = 0
    while index < 8 {
      let sum = UInt64(lhs[index]) + UInt64(rhs[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    return result
  }

  static func truncate(_ words: [UInt64]) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var index = 0
    while index < 8 {
      result[index] = UInt32(truncatingIfNeeded: words[index])
      index += 1
    }
    return result
  }
}
