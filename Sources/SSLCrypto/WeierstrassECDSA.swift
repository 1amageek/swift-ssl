import SSLCore

/// Verification-only ECDSA for NIST P-384.
///
/// The public key, digest, and signature are public verification inputs. The
/// fixed-width arithmetic therefore has no secret-dependent timing contract.
public enum P384ECDSA: DigestSignatureVerifier {
  public typealias PublicKey = P384PublicKey

  public static let signatureByteCount = 96

  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing P384PublicKey
  ) throws(CryptoInputError) -> Bool {
    try publicKey.withBorrowedPoint {
      (point: WeierstrassECDSA.Point) throws(CryptoInputError) -> Bool in
      try WeierstrassECDSA.verify(
        signature: signature,
        messageHash: messageHash,
        publicPoint: point,
        curve: .p384
      )
    }
  }
}

/// Verification-only ECDSA for NIST P-521.
///
/// The public key, digest, and signature are public verification inputs. The
/// fixed-width arithmetic therefore has no secret-dependent timing contract.
public enum P521ECDSA: DigestSignatureVerifier {
  public typealias PublicKey = P521PublicKey

  public static let signatureByteCount = 132

  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing P521PublicKey
  ) throws(CryptoInputError) -> Bool {
    try publicKey.withBorrowedPoint {
      (point: WeierstrassECDSA.Point) throws(CryptoInputError) -> Bool in
      try WeierstrassECDSA.verify(
        signature: signature,
        messageHash: messageHash,
        publicPoint: point,
        curve: .p521
      )
    }
  }
}

public struct P384PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount = 97
  public static let compressedByteCount = 49
  let storage: OwnedBytes
  let point: WeierstrassECDSA.Point

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.uncompressedByteCount else {
      throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
    }
    guard let point = WeierstrassECDSA.Point.decode(bytes, curve: .p384) else {
      throw .invalidPeerKey
    }
    storage = OwnedBytes(copying: bytes)
    self.point = point
  }

  public init(compressedBytes: Span<UInt8>) throws(CryptoInputError) {
    guard compressedBytes.count == Self.compressedByteCount else {
      throw .invalidLength(expected: Self.compressedByteCount, actual: compressedBytes.count)
    }
    guard let point = WeierstrassECDSA.Point.decodeCompressed(compressedBytes, curve: .p384),
      let encoded = point.encoded(curve: .p384)
    else { throw .invalidPeerKey }
    storage = OwnedBytes(consuming: encoded)
    self.point = point
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func compressedBytes() -> ContiguousArray<UInt8> {
    point.encodedCompressed(curve: .p384) ?? []
  }

  fileprivate borrowing func withBorrowedPoint<Result: ~Copyable, Failure: Error>(
    _ body: (WeierstrassECDSA.Point) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(point)
  }
}

public struct P521PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount = 133
  public static let compressedByteCount = 67
  let storage: OwnedBytes
  let point: WeierstrassECDSA.Point

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.uncompressedByteCount else {
      throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
    }
    guard let point = WeierstrassECDSA.Point.decode(bytes, curve: .p521) else {
      throw .invalidPeerKey
    }
    storage = OwnedBytes(copying: bytes)
    self.point = point
  }

  public init(compressedBytes: Span<UInt8>) throws(CryptoInputError) {
    guard compressedBytes.count == Self.compressedByteCount else {
      throw .invalidLength(expected: Self.compressedByteCount, actual: compressedBytes.count)
    }
    guard let point = WeierstrassECDSA.Point.decodeCompressed(compressedBytes, curve: .p521),
      let encoded = point.encoded(curve: .p521)
    else { throw .invalidPeerKey }
    storage = OwnedBytes(consuming: encoded)
    self.point = point
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func compressedBytes() -> ContiguousArray<UInt8> {
    point.encodedCompressed(curve: .p521) ?? []
  }

  fileprivate borrowing func withBorrowedPoint<Result: ~Copyable, Failure: Error>(
    _ body: (WeierstrassECDSA.Point) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(point)
  }
}

enum WeierstrassECDSA {
  enum Curve {
    case p384
    case p521

    // These constants are shared by the arithmetic fast paths. Keeping the
    // modulus identity explicit lets moduloMultiply select a reduction law
    // without carrying a curve tag through every value operation.
    static let p384Prime = FixedUInt(
      hex:
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
      byteCount: 48
    )
    static let p521Prime = FixedUInt(
      hex:
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      byteCount: 66
    )

    var byteCount: Int { self == .p384 ? 48 : 66 }
    var bitCount: Int { self == .p384 ? 384 : 521 }
  var signatureByteCount: Int { byteCount * 2 }
    var uncompressedByteCount: Int { 1 + byteCount * 2 }
    var compressedByteCount: Int { 1 + byteCount }
    var unusedTopBits: UInt8 { self == .p521 ? 7 : 0 }

    var prime: FixedUInt {
      switch self {
      case .p384:
        return Self.p384Prime
      case .p521:
        return Self.p521Prime
      }
    }

    var order: FixedUInt {
      switch self {
      case .p384:
        return FixedUInt(
          hex:
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
          byteCount: 48)
      case .p521:
        return FixedUInt(
          hex:
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
          byteCount: 66)
      }
    }

    var curveB: FixedUInt {
      switch self {
      case .p384:
        return FixedUInt(
          hex:
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
          byteCount: 48)
      case .p521:
        return FixedUInt(
          hex:
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
          byteCount: 66)
      }
    }

    var generatorX: FixedUInt {
      switch self {
      case .p384:
        return FixedUInt(
          hex:
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
          byteCount: 48)
      case .p521:
        return FixedUInt(
          hex:
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
          byteCount: 66)
      }
    }

    var generatorY: FixedUInt {
      switch self {
      case .p384:
        return FixedUInt(
          hex:
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
          byteCount: 48)
      case .p521:
        return FixedUInt(
          hex:
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
          byteCount: 66)
      }
    }
  }

  static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    publicPoint: Point,
    curve: Curve
  ) throws(CryptoInputError) -> Bool {
    guard signature.count == curve.signatureByteCount else {
      throw .invalidLength(expected: curve.signatureByteCount, actual: signature.count)
    }
    guard !messageHash.isEmpty else {
      throw .invalidLength(expected: 1, actual: 0)
    }
    let r = FixedUInt(bytes: signature.extracting(0..<curve.byteCount), byteCount: curve.byteCount)
    let s = FixedUInt(
      bytes: signature.extracting(curve.byteCount..<curve.signatureByteCount),
      byteCount: curve.byteCount)
    guard !r.isZero, !s.isZero, r < curve.order, s < curve.order else {
      throw .nonCanonicalEncoding
    }
    let digest = FixedUInt(truncatingDigest: messageHash, curve: curve)
    let inverse = s.power(
      curve.order.subtractingSmall(2),
      modulus: curve.order,
      bitCount: curve.bitCount
    )
    let u1 = digest.moduloMultiply(inverse, modulus: curve.order)
    let u2 = r.moduloMultiply(inverse, modulus: curve.order)
    let first = Point.scalarMultiply(Point.generator(curve), scalar: u1, curve: curve)
    let second = Point.scalarMultiply(publicPoint, scalar: u2, curve: curve)
    guard let affine = first.adding(second, curve: curve).affine(curve: curve) else {
      return false
    }
    return affine.x.modulo(curve.order) == r
  }

  struct FixedUInt: Equatable, Comparable {
    var words: ContiguousArray<UInt32>

    init(byteCount: Int) {
      words = ContiguousArray(repeating: 0, count: (byteCount + 3) / 4)
    }

    init(bytes: Span<UInt8>, byteCount: Int) {
      var words = ContiguousArray<UInt32>(repeating: 0, count: (byteCount + 3) / 4)
      var index = 0
      while index < bytes.count {
        let destination = bytes.count - 1 - index
        let word = index / 4
        words[word] |= UInt32(bytes[destination]) << UInt32((index & 3) * 8)
        index += 1
      }
      self.words = words
    }

    init(truncatingDigest bytes: Span<UInt8>, curve: Curve) {
      let count = curve.byteCount
      if bytes.count >= count {
        self.init(bytes: bytes.extracting(0..<count), byteCount: count)
      } else {
        var padded = ContiguousArray<UInt8>(repeating: 0, count: count)
        let offset = count - bytes.count
        var index = 0
        while index < bytes.count {
          padded[offset + index] = bytes[index]
          index += 1
        }
        self.init(bytes: padded.span, byteCount: count)
      }
      if curve == .p521 {
        var mutable = ContiguousArray(words)
        mutable[mutable.count - 1] &= 0x0000_01FF
        self = FixedUInt(words: mutable)
      }
    }

    init(hex: String, byteCount: Int) {
      var bytes = ContiguousArray<UInt8>()
      var high: UInt8 = 0
      var haveHigh = false
      for character in hex.utf8 {
        let value: UInt8
        switch character {
        case 0x30...0x39: value = character - 0x30
        case 0x41...0x46: value = character - 0x41 + 10
        case 0x61...0x66: value = character - 0x61 + 10
        default: continue
        }
        if haveHigh {
          bytes.append((high << 4) | value)
          haveHigh = false
        } else {
          high = value
          haveHigh = true
        }
      }
      self.init(bytes: bytes.span, byteCount: byteCount)
    }

    init(words: ContiguousArray<UInt32>) { self.words = words }

    static func one(byteCount: Int) -> FixedUInt {
      var words = ContiguousArray<UInt32>(repeating: 0, count: (byteCount + 3) / 4)
      words[0] = 1
      return FixedUInt(words: words)
    }

    var isZero: Bool {
      var result: UInt32 = 0
      for word in words { result |= word }
      return result == 0
    }

    mutating func wipe() {
      var index = 0
      while index < words.count {
        words[index] = 0
        index += 1
      }
    }

    func encoded(byteCount: Int) -> ContiguousArray<UInt8> {
      var result = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
      var index = 0
      while index < byteCount {
        let word = index / 4
        let shift = UInt32((index & 3) * 8)
        result[byteCount - 1 - index] = UInt8(truncatingIfNeeded: words[word] >> shift)
        index += 1
      }
      return result
    }

    func modulo(_ modulus: FixedUInt) -> FixedUInt {
      var value = self
      while value >= modulus { value = value - modulus }
      return value
    }

    func moduloAdd(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
      let sum = self + other
      if sum < self {
        let complement = FixedUInt(byteCount: words.count * 4) - modulus
        return sum + complement
      }
      if sum >= modulus { return sum - modulus }
      return sum
    }

    func moduloSubtract(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
      if self >= other { return self - other }
      return modulus - (other - self)
    }

    func moduloMultiply(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
      if modulus == Curve.p384Prime {
        return p384PrimeMultiply(other)
      }
      if modulus == Curve.p521Prime {
        return p521PrimeMultiply(other)
      }

      // The order moduli do not have a pseudo-Mersenne reduction law. Keep
      // the constant-time reference reduction for those scalar operations.
      var product = ContiguousArray<UInt64>(repeating: 0, count: words.count * 2)
      var i = 0
      while i < words.count {
        var carry: UInt64 = 0
        var j = 0
        while j < words.count {
          let value = UInt64(words[i]) * UInt64(other.words[j]) + product[i + j] + carry
          product[i + j] = value & 0xFFFF_FFFF
          carry = value >> 32
          j += 1
        }
        var index = i + words.count
        while carry != 0 && index < product.count {
          let value = product[index] + carry
          product[index] = value & 0xFFFF_FFFF
          carry = value >> 32
          index += 1
        }
        i += 1
      }

      var remainder = ContiguousArray<UInt64>(repeating: 0, count: words.count + 1)
      var bit = product.count * 32 - 1
      while bit >= 0 {
        var carry = (product[bit >> 5] >> UInt64(bit & 31)) & 1
        var index = 0
        while index < remainder.count {
          let value = (remainder[index] << 1) | carry
          remainder[index] = value & 0xFFFF_FFFF
          carry = value >> 32
          index += 1
        }
        if remainder[words.count] != 0
          || FixedUInt(truncating: remainder, count: words.count) >= modulus
        {
          var borrow: UInt64 = 0
          index = 0
          while index < words.count {
            let minuend = remainder[index]
            let subtrahend = UInt64(modulus.words[index]) + borrow
            if minuend < subtrahend {
              remainder[index] = (UInt64(1) << 32) + minuend - subtrahend
              borrow = 1
            } else {
              remainder[index] = minuend - subtrahend
              borrow = 0
            }
            index += 1
          }
          remainder[words.count] -= borrow
        }
        bit -= 1
      }
      return FixedUInt(truncating: remainder, count: words.count)
    }

    /// Multiplies two 384-bit values and reduces with
    /// p = 2^384 - 2^128 - 2^96 + 2^32 - 1. The signed accumulator is
    /// bounded by a few dozen limbs and is normalized only once, avoiding the
    /// per-bit temporary FixedUInt allocations of the reference path.
    private func p384PrimeMultiply(_ other: FixedUInt) -> FixedUInt {
      var product = ContiguousArray<Int64>(repeating: 0, count: 24)
      var i = 0
      while i < 12 {
        var carry: UInt64 = 0
        var j = 0
        while j < 12 {
          let value = UInt64(words[i]) * UInt64(other.words[j])
            + UInt64(product[i + j]) + carry
          product[i + j] = Int64(value & 0xFFFF_FFFF)
          carry = value >> 32
          j += 1
        }
        var index = i + 12
        while carry != 0 {
          let value = UInt64(product[index]) + carry
          product[index] = Int64(value & 0xFFFF_FFFF)
          carry = value >> 32
          index += 1
        }
        i += 1
      }

      // 2^384 = 2^128 + 2^96 - 2^32 + 1 (mod p).
      i = 23
      while i >= 12 {
        let high = product[i]
        product[i] = 0
        let low = i - 12
        product[low] += high
        product[low + 4] += high
        product[low + 3] += high
        product[low + 1] -= high
        i -= 1
      }

      var normalized = ContiguousArray<UInt32>(repeating: 0, count: 12)
      var carry: Int64 = 0
      i = 0
      while i < 12 {
        let value = product[i] + carry
        if value >= 0 {
          normalized[i] = UInt32(truncatingIfNeeded: value)
          carry = value >> 32
        } else {
          let borrow = (-value + 0xFFFF_FFFF) >> 32
          normalized[i] = UInt32(truncatingIfNeeded: value + (borrow << 32))
          carry = -borrow
        }
        i += 1
      }

      // A final carry represents carry * 2^384; fold it with the same law.
      // At most two passes are required for a 768-bit product, but the small
      // fixed bound also protects this internal routine from accidental loops.
      var pass = 0
      while carry != 0 && pass < 3 {
        i = 0
        while i < 12 {
          product[i] = Int64(normalized[i])
          i += 1
        }
        product[0] += carry
        product[4] += carry
        product[3] += carry
        product[1] -= carry

        var nextCarry: Int64 = 0
        i = 0
        while i < 12 {
          let value = product[i] + nextCarry
          if value >= 0 {
            normalized[i] = UInt32(truncatingIfNeeded: value)
            nextCarry = value >> 32
          } else {
            let borrow = (-value + 0xFFFF_FFFF) >> 32
            normalized[i] = UInt32(truncatingIfNeeded: value + (borrow << 32))
            nextCarry = -borrow
          }
          i += 1
        }
        carry = nextCarry
        pass += 1
      }
      precondition(carry == 0, "P-384 reduction carry did not converge")

      var result = FixedUInt(words: normalized)
      while result >= Curve.p384Prime {
        result = result - Curve.p384Prime
      }
      return result
    }

    /// Multiplies two 521-bit values and reduces with p = 2^521 - 1.
    /// High limbs are folded a word at a time, so the reduction is linear in
    /// the limb count rather than in the number of product bits.
    private func p521PrimeMultiply(_ other: FixedUInt) -> FixedUInt {
      var product = ContiguousArray<UInt64>(repeating: 0, count: 34)
      var i = 0
      while i < 17 {
        var carry: UInt64 = 0
        var j = 0
        while j < 17 {
          let value = UInt64(words[i]) * UInt64(other.words[j])
            + product[i + j] + carry
          product[i + j] = value & 0xFFFF_FFFF
          carry = value >> 32
          j += 1
        }
        var index = i + 17
        while carry != 0 {
          let value = product[index] + carry
          product[index] = value & 0xFFFF_FFFF
          carry = value >> 32
          index += 1
        }
        i += 1
      }

      // Each high 32-bit word at index i contributes at index i-17 shifted
      // by 23 bits because 32 * 17 - 521 = 23.
      i = 33
      while i >= 17 {
        let high = product[i]
        product[i] = 0
        let target = i - 17
        product[target] += (high << 23) & 0xFFFF_FFFF
        product[target + 1] += high >> 9

        var carry: UInt64 = 0
        var index = target
        while index <= target + 1 {
          let value = product[index] + carry
          product[index] = value & 0xFFFF_FFFF
          carry = value >> 32
          index += 1
        }
        while carry != 0 {
          let value = product[index] + carry
          product[index] = value & 0xFFFF_FFFF
          carry = value >> 32
          index += 1
        }
        i -= 1
      }

      // The top nine bits of limb 16 represent 2^521 and fold back to limb 0.
      let highBits = product[16] >> 9
      product[16] &= 0x1FF
      product[0] += highBits
      var carry: UInt64 = 0
      i = 0
      while i < 17 {
        let value = product[i] + carry
        product[i] = value & 0xFFFF_FFFF
        carry = value >> 32
        i += 1
      }
      if carry != 0 { product[17] += carry }

      // The carry above can create one more high word; fold it once more.
      if product[17] != 0 {
        let high = product[17]
        product[17] = 0
        product[0] += (high << 23) & 0xFFFF_FFFF
        product[1] += high >> 9
        carry = 0
        i = 0
        while i < 17 {
          let value = product[i] + carry
          product[i] = value & 0xFFFF_FFFF
          carry = value >> 32
          i += 1
        }
        product[16] = (product[16] & 0x1FF) + carry
      }

      var result = FixedUInt(
        words: ContiguousArray(product[0..<17].map { UInt32(truncatingIfNeeded: $0) })
      )
      while result >= Curve.p521Prime {
        result = result - Curve.p521Prime
      }
      return result
    }

    func power(
      _ exponent: FixedUInt,
      modulus: FixedUInt,
      bitCount: Int
    ) -> FixedUInt {
      var result = FixedUInt.one(byteCount: words.count * 4)
      var bit = bitCount - 1
      while bit >= 0 {
        result = result.moduloMultiply(result, modulus: modulus)
        if ((exponent.words[bit >> 5] >> UInt32(bit & 31)) & 1) != 0 {
          result = result.moduloMultiply(self, modulus: modulus)
        }
        bit -= 1
      }
      return result
    }

    static func - (lhs: FixedUInt, rhs: FixedUInt) -> FixedUInt {
      var result = ContiguousArray<UInt32>(repeating: 0, count: lhs.words.count)
      var borrow: UInt64 = 0
      var index = 0
      while index < result.count {
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
      return FixedUInt(words: result)
    }

    static func + (lhs: FixedUInt, rhs: FixedUInt) -> FixedUInt {
      var result = ContiguousArray<UInt32>(repeating: 0, count: lhs.words.count)
      var carry: UInt64 = 0
      var index = 0
      while index < result.count {
        let sum = UInt64(lhs.words[index]) + UInt64(rhs.words[index]) + carry
        result[index] = UInt32(truncatingIfNeeded: sum)
        carry = sum >> 32
        index += 1
      }
      return FixedUInt(words: result)
    }

    static func < (lhs: FixedUInt, rhs: FixedUInt) -> Bool {
      var index = lhs.words.count - 1
      while index >= 0 {
        if lhs.words[index] != rhs.words[index] { return lhs.words[index] < rhs.words[index] }
        index -= 1
      }
      return false
    }

    init(truncating words: ContiguousArray<UInt64>, count: Int) {
      var result = ContiguousArray<UInt32>(repeating: 0, count: count)
      var index = 0
      while index < count {
        result[index] = UInt32(truncatingIfNeeded: words[index])
        index += 1
      }
      self.words = result
    }
  }

  struct Point: Equatable {
    let x: FixedUInt
    let y: FixedUInt
    let z: FixedUInt

    static func generator(_ curve: Curve) -> Point {
      Point(x: curve.generatorX, y: curve.generatorY, z: FixedUInt.one(byteCount: curve.byteCount))
    }

    static func decode(_ bytes: Span<UInt8>, curve: Curve) -> Point? {
      guard bytes.count == 1 + curve.byteCount * 2, bytes[0] == 0x04 else { return nil }
      let x = FixedUInt(
        bytes: bytes.extracting(1..<(1 + curve.byteCount)), byteCount: curve.byteCount)
      let y = FixedUInt(
        bytes: bytes.extracting((1 + curve.byteCount)..<bytes.count), byteCount: curve.byteCount)
      guard x < curve.prime, y < curve.prime else { return nil }
      let point = Point(x: x, y: y, z: FixedUInt.one(byteCount: curve.byteCount))
      return point.isOnCurve(curve) ? point : nil
    }

    static func decodeCompressed(_ bytes: Span<UInt8>, curve: Curve) -> Point? {
      guard bytes.count == curve.compressedByteCount,
        bytes[0] == 0x02 || bytes[0] == 0x03
      else { return nil }
      let x = FixedUInt(
        bytes: bytes.extracting(1..<bytes.count), byteCount: curve.byteCount
      )
      guard x < curve.prime else { return nil }
      let xSquared = x.moduloMultiply(x, modulus: curve.prime)
      let rhs = xSquared.moduloMultiply(x, modulus: curve.prime)
        .moduloSubtract(
          x.moduloAdd(x, modulus: curve.prime).moduloAdd(x, modulus: curve.prime),
          modulus: curve.prime
        )
        .moduloAdd(curve.curveB, modulus: curve.prime)
      let exponent = curve.prime.addingSmall(1)
      let squareRoot = rhs.power(
        exponent.dividedBySmall(4),
        modulus: curve.prime,
        bitCount: curve.bitCount
      )
      guard squareRoot.moduloMultiply(squareRoot, modulus: curve.prime) == rhs else {
        return nil
      }
      let encoded = squareRoot.encoded(byteCount: curve.byteCount)
      let parity = encoded[encoded.count - 1] & 1
      let y = parity == (bytes[0] & 1) ? squareRoot : curve.prime - squareRoot
      let point = Point(x: x, y: y, z: FixedUInt.one(byteCount: curve.byteCount))
      return point.isOnCurve(curve) ? point : nil
    }

    var isInfinity: Bool { z.isZero }

    func isOnCurve(_ curve: Curve) -> Bool {
      guard !isInfinity else { return false }
      let left = y.moduloMultiply(y, modulus: curve.prime)
      let x2 = x.moduloMultiply(x, modulus: curve.prime)
      let x3 = x2.moduloMultiply(x, modulus: curve.prime)
      let threeX = x.moduloAdd(x, modulus: curve.prime).moduloAdd(x, modulus: curve.prime)
      let right = x3.moduloSubtract(threeX, modulus: curve.prime)
        .moduloAdd(curve.curveB, modulus: curve.prime)
      return left == right
    }

    func affine(curve: Curve) -> Point? {
      guard !isInfinity else { return nil }
      let exponent = curve.prime.subtractingSmall(2)
      let inverse = z.power(
        exponent,
        modulus: curve.prime,
        bitCount: curve.bitCount
      )
      let inverseSquared = inverse.moduloMultiply(inverse, modulus: curve.prime)
      let affineX = x.moduloMultiply(inverseSquared, modulus: curve.prime)
      let affineY = y.moduloMultiply(inverseSquared, modulus: curve.prime).moduloMultiply(
        inverse, modulus: curve.prime)
      return Point(x: affineX, y: affineY, z: FixedUInt.one(byteCount: curve.byteCount))
    }

    func encoded(curve: Curve) -> ContiguousArray<UInt8>? {
      guard let affine = affine(curve: curve) else { return nil }
      var result = ContiguousArray<UInt8>(repeating: 0, count: 1 + curve.byteCount * 2)
      result[0] = 0x04
      let x = affine.x.encoded(byteCount: curve.byteCount)
      let y = affine.y.encoded(byteCount: curve.byteCount)
      var index = 0
      while index < curve.byteCount {
        result[1 + index] = x[index]
        result[1 + curve.byteCount + index] = y[index]
        index += 1
      }
      return result
    }

    func encodedCompressed(curve: Curve) -> ContiguousArray<UInt8>? {
      guard let affine = affine(curve: curve) else { return nil }
      var result = ContiguousArray<UInt8>(repeating: 0, count: curve.compressedByteCount)
      let encodedX = affine.x.encoded(byteCount: curve.byteCount)
      result[0] = affine.y.encoded(byteCount: curve.byteCount).last! & 1 == 0 ? 0x02 : 0x03
      var index = 0
      while index < curve.byteCount {
        result[index + 1] = encodedX[index]
        index += 1
      }
      return result
    }

    func doubled(curve: Curve) -> Point {
      guard !isInfinity, !y.isZero else { return Point.infinity(curve) }
      let p = curve.prime
      let ySquared = y.moduloMultiply(y, modulus: p)
      let s = FixedUInt(byteCount: curve.byteCount).addingSmall(4).moduloMultiply(x, modulus: p)
        .moduloMultiply(ySquared, modulus: p)
      let zSquared = z.moduloMultiply(z, modulus: p)
      let m = FixedUInt(byteCount: curve.byteCount).addingSmall(3)
        .moduloMultiply(x.moduloSubtract(zSquared, modulus: p), modulus: p)
        .moduloMultiply(x.moduloAdd(zSquared, modulus: p), modulus: p)
      let x3 = m.moduloMultiply(m, modulus: p)
        .moduloSubtract(s, modulus: p).moduloSubtract(s, modulus: p)
      let y4 = ySquared.moduloMultiply(ySquared, modulus: p)
      let y3 = m.moduloMultiply(s.moduloSubtract(x3, modulus: p), modulus: p)
        .moduloSubtract(
          y4.moduloMultiply(FixedUInt(byteCount: curve.byteCount).addingSmall(8), modulus: p),
          modulus: p)
      let z3 = FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(y, modulus: p)
        .moduloMultiply(z, modulus: p)
      return Point(x: x3, y: y3, z: z3)
    }

    func adding(_ other: Point, curve: Curve) -> Point {
      guard !isInfinity else { return other }
      guard !other.isInfinity else { return self }
      let p = curve.prime
      let z1Squared = z.moduloMultiply(z, modulus: p)
      let z2Squared = other.z.moduloMultiply(other.z, modulus: p)
      let u1 = x.moduloMultiply(z2Squared, modulus: p)
      let u2 = other.x.moduloMultiply(z1Squared, modulus: p)
      let s1 = y.moduloMultiply(other.z, modulus: p).moduloMultiply(z2Squared, modulus: p)
      let s2 = other.y.moduloMultiply(z, modulus: p).moduloMultiply(z1Squared, modulus: p)
      if u1 == u2 { return s1 == s2 ? doubled(curve: curve) : Point.infinity(curve) }
      let h = u2.moduloSubtract(u1, modulus: p)
      let i = FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(h, modulus: p)
        .moduloMultiply(
          FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(h, modulus: p),
          modulus: p)
      let j = h.moduloMultiply(i, modulus: p)
      let r = FixedUInt(byteCount: curve.byteCount).addingSmall(2)
        .moduloMultiply(s2.moduloSubtract(s1, modulus: p), modulus: p)
      let v = u1.moduloMultiply(i, modulus: p)
      let x3 = r.moduloMultiply(r, modulus: p).moduloSubtract(j, modulus: p)
        .moduloSubtract(v, modulus: p).moduloSubtract(v, modulus: p)
      let y3 = r.moduloMultiply(v.moduloSubtract(x3, modulus: p), modulus: p)
        .moduloSubtract(
          s1.moduloMultiply(j, modulus: p)
            .moduloMultiply(FixedUInt(byteCount: curve.byteCount).addingSmall(2), modulus: p),
          modulus: p
        )
      let zSum = z.moduloAdd(other.z, modulus: p)
      let z3 = zSum.moduloMultiply(zSum, modulus: p)
        .moduloSubtract(z1Squared, modulus: p)
        .moduloSubtract(z2Squared, modulus: p)
        .moduloMultiply(h, modulus: p)
      return Point(x: x3, y: y3, z: z3)
    }

    static func scalarMultiply(_ point: Point, scalar: FixedUInt, curve: Curve) -> Point {
      var result = Point.infinity(curve)
      var bit = curve.bitCount - 1
      while bit >= 0 {
        result = result.doubled(curve: curve)
        if ((scalar.words[bit >> 5] >> UInt32(bit & 31)) & 1) != 0 {
          result = result.adding(point, curve: curve)
        }
        bit -= 1
      }
      return result
    }

    /// Secret-scalar multiplication with a fixed four-bit schedule.
    ///
    /// The table is scanned linearly for every nibble. The scalar controls
    /// only arithmetic masks and never an address or loop bound. Complete
    /// Jacobian addition handles zero, equal, inverse, and infinity cases
    /// without a secret-dependent branch.
    static func scalarMultiplySecret(
      _ point: Point,
      scalar: FixedUInt,
      curve: Curve
    ) -> Point {
      var table = ContiguousArray<Point>(repeating: Point.infinity(curve), count: 16)
      table[1] = point
      var index = 2
      while index < table.count {
        table[index] = table[index - 1].adding(point, curve: curve)
        index += 1
      }

      var result = Point.infinity(curve)
      var nibble = (curve.bitCount + 3) / 4 - 1
      while nibble >= 0 {
        var doubling = 0
        while doubling < 4 {
          result = result.doubledComplete(curve: curve)
          doubling += 1
        }
        let digit = scalar.nibble(at: nibble)
        let selected = selectPointFromTable(table: table, digit: digit, curve: curve)
        result = result.addingComplete(selected, curve: curve)
        nibble -= 1
      }
      return result
    }

    static func infinity(_ curve: Curve) -> Point {
      Point(
        x: FixedUInt(byteCount: curve.byteCount), y: FixedUInt(byteCount: curve.byteCount),
        z: FixedUInt(byteCount: curve.byteCount))
    }
  }
}

extension WeierstrassECDSA.FixedUInt {
  fileprivate func addingSmall(_ value: UInt32) -> Self {
    var result = words
    var carry = UInt64(value)
    var index = 0
    while carry != 0 && index < result.count {
      let sum = UInt64(result[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    return Self(words: result)
  }

  func subtractingSmall(_ value: UInt32) -> Self {
    var result = words
    var borrow = UInt64(value)
    var index = 0
    while borrow != 0 && index < result.count {
      let minuend = UInt64(result[index])
      if minuend < borrow {
        result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - borrow)
        borrow = 1
      } else {
        result[index] = UInt32(truncatingIfNeeded: minuend - borrow)
        borrow = 0
      }
      index += 1
    }
    return Self(words: result)
  }

  func dividedBySmall(_ divisor: UInt32) -> Self {
    precondition(divisor != 0)
    var result = ContiguousArray<UInt32>(repeating: 0, count: words.count)
    var remainder: UInt64 = 0
    var index = words.count
    while index > 0 {
      index -= 1
      let value = (remainder << 32) | UInt64(words[index])
      result[index] = UInt32(value / UInt64(divisor))
      remainder = value % UInt64(divisor)
    }
    return Self(words: result)
  }

  func nibble(at index: Int) -> UInt8 {
    precondition(index >= 0)
    let bit = index * 4
    let word = bit >> 5
    let shift = bit & 31
    guard word < words.count else { return 0 }
    return UInt8(truncatingIfNeeded: words[word] >> UInt32(shift)) & 0x0F
  }

  var zeroMask: UInt32 {
    var value: UInt32 = 0
    for word in words { value |= word }
    let nonzero = (value | (0 &- value)) >> 31
    return 0 &- (nonzero ^ 1)
  }

  static func select(mask: UInt32, _ selected: Self, _ alternative: Self) -> Self {
    var result = ContiguousArray<UInt32>(repeating: 0, count: selected.words.count)
    var index = 0
    while index < result.count {
      result[index] = (selected.words[index] & mask)
        | (alternative.words[index] & ~mask)
      index += 1
    }
    return Self(words: result)
  }
}

extension WeierstrassECDSA.Point {
  func doubledComplete(curve: WeierstrassECDSA.Curve) -> Self {
    let p = curve.prime
    let ySquared = y.moduloMultiply(y, modulus: p)
    let s = x.moduloMultiply(ySquared, modulus: p)
      .moduloMultiply(WeierstrassECDSA.FixedUInt(byteCount: curve.byteCount).addingSmall(4), modulus: p)
    let zSquared = z.moduloMultiply(z, modulus: p)
    let m = x.moduloSubtract(zSquared, modulus: p)
      .moduloMultiply(x.moduloAdd(zSquared, modulus: p), modulus: p)
      .moduloMultiply(WeierstrassECDSA.FixedUInt(byteCount: curve.byteCount).addingSmall(3), modulus: p)
    let x3 = m.moduloMultiply(m, modulus: p).moduloSubtract(s, modulus: p)
      .moduloSubtract(s, modulus: p)
    let y4 = ySquared.moduloMultiply(ySquared, modulus: p)
    let y3 = m.moduloMultiply(s.moduloSubtract(x3, modulus: p), modulus: p)
      .moduloSubtract(
        y4.moduloMultiply(WeierstrassECDSA.FixedUInt(byteCount: curve.byteCount).addingSmall(8), modulus: p),
        modulus: p
      )
    let z3 = y.moduloMultiply(z, modulus: p)
      .moduloMultiply(WeierstrassECDSA.FixedUInt(byteCount: curve.byteCount).addingSmall(2), modulus: p)
    let generic = Self(x: x3, y: y3, z: z3)
    let exceptional = Self.infinity(curve)
    return Self.select(mask: z.zeroMask | y.zeroMask, exceptional, generic)
  }

  func addingComplete(_ other: Self, curve: WeierstrassECDSA.Curve) -> Self {
    let p = curve.prime
    let z1Squared = z.moduloMultiply(z, modulus: p)
    let z2Squared = other.z.moduloMultiply(other.z, modulus: p)
    let u1 = x.moduloMultiply(z2Squared, modulus: p)
    let u2 = other.x.moduloMultiply(z1Squared, modulus: p)
    let s1 = y.moduloMultiply(other.z, modulus: p).moduloMultiply(z2Squared, modulus: p)
    let s2 = other.y.moduloMultiply(z, modulus: p).moduloMultiply(z1Squared, modulus: p)
    let h = u2.moduloSubtract(u1, modulus: p)
    let h2 = h.moduloAdd(h, modulus: p)
    let i = h2.moduloMultiply(h2, modulus: p)
    let j = h.moduloMultiply(i, modulus: p)
    let rDifference = s2.moduloSubtract(s1, modulus: p)
    let r = rDifference.moduloAdd(rDifference, modulus: p)
    let v = u1.moduloMultiply(i, modulus: p)
    let zSum = z.moduloAdd(other.z, modulus: p)
    let z3 = zSum.moduloMultiply(zSum, modulus: p)
      .moduloSubtract(z1Squared, modulus: p)
      .moduloSubtract(z2Squared, modulus: p)
      .moduloMultiply(h, modulus: p)
    let generic = Self(
      x: r.moduloMultiply(r, modulus: p).moduloSubtract(j, modulus: p)
        .moduloSubtract(v, modulus: p).moduloSubtract(v, modulus: p),
      y: r.moduloMultiply(
        v.moduloSubtract(
          r.moduloMultiply(r, modulus: p).moduloSubtract(j, modulus: p)
            .moduloSubtract(v, modulus: p).moduloSubtract(v, modulus: p),
          modulus: p
        ), modulus: p
      ).moduloSubtract(
        s1.moduloMultiply(j, modulus: p)
          .moduloMultiply(WeierstrassECDSA.FixedUInt(byteCount: curve.byteCount).addingSmall(2), modulus: p),
        modulus: p
      ),
      z: z3
    )
    let hZero = h.zeroMask
    let rZero = r.zeroMask
    let equalMask = hZero & rZero
    let inverseMask = hZero & ~rZero
    var result = generic
    result = Self.select(mask: equalMask, doubledComplete(curve: curve), result)
    result = Self.select(mask: inverseMask, .infinity(curve), result)
    result = Self.select(mask: other.z.zeroMask, self, result)
    result = Self.select(mask: z.zeroMask, other, result)
    return result
  }

  static func select(mask: UInt32, _ selected: Self, _ alternative: Self) -> Self {
    Self(
      x: WeierstrassECDSA.FixedUInt.select(mask: mask, selected.x, alternative.x),
      y: WeierstrassECDSA.FixedUInt.select(mask: mask, selected.y, alternative.y),
      z: WeierstrassECDSA.FixedUInt.select(mask: mask, selected.z, alternative.z)
    )
  }
}

private func selectPointFromTable(
  table: ContiguousArray<WeierstrassECDSA.Point>,
  digit: UInt8,
  curve: WeierstrassECDSA.Curve
) -> WeierstrassECDSA.Point {
  var result = WeierstrassECDSA.Point.infinity(curve)
  var index = 0
  while index < table.count {
    let difference = UInt32(index ^ Int(digit))
    let nonzero = (difference | (0 &- difference)) >> 31
    let mask = 0 &- (nonzero ^ 1)
    result = WeierstrassECDSA.Point.select(mask: mask, table[index], result)
    index += 1
  }
  return result
}
