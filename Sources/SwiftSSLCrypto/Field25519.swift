import SwiftSSLCore

/// Radix-2^16 field storage retained exclusively for Ed25519 point arithmetic.
struct Field25519 {
  private static let base: Int64 = 65_536
  private var limbs: [Int64]

  init() { limbs = [Int64](repeating: 0, count: 16) }
  init(one: Bool) {
    limbs = [Int64](repeating: 0, count: 16)
    limbs[0] = one ? 1 : 0
  }
  init(constant: Int64) {
    limbs = [Int64](repeating: 0, count: 16)
    limbs[0] = constant
    normalize()
  }

  init(bytes: Span<UInt8>) {
    limbs = [Int64](repeating: 0, count: 16)
    var index = 0
    while index < 16 {
      limbs[index] = Int64(bytes[index * 2]) | (Int64(bytes[index * 2 + 1]) << 8)
      index += 1
    }
    limbs[15] &= 0x7fff
    normalize()
  }

  var bytes: ContiguousArray<UInt8> {
    var value = self
    value.normalize()
    var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var index = 0
    while index < 16 {
      result[index * 2] = UInt8(truncatingIfNeeded: value.limbs[index])
      result[index * 2 + 1] = UInt8(truncatingIfNeeded: value.limbs[index] >> 8)
      index += 1
    }
    result[31] &= 0x7f
    return result
  }

  static func + (lhs: Field25519, rhs: Field25519) -> Field25519 {
    var result = Field25519()
    var index = 0
    while index < 16 {
      result.limbs[index] = lhs.limbs[index] + rhs.limbs[index]
      index += 1
    }
    result.normalize()
    return result
  }

  static func - (lhs: Field25519, rhs: Field25519) -> Field25519 {
    var result = Field25519()
    var index = 0
    while index < 16 {
      result.limbs[index] = lhs.limbs[index] - rhs.limbs[index]
      index += 1
    }
    result.normalize()
    return result
  }

  static func * (lhs: Field25519, rhs: Field25519) -> Field25519 {
    var product = [Int64](repeating: 0, count: 32)
    var i = 0
    while i < 16 {
      var j = 0
      while j < 16 {
        product[i + j] += lhs.limbs[i] * rhs.limbs[j]
        j += 1
      }
      i += 1
    }
    i = 31
    while i >= 16 {
      product[i - 16] += product[i] * 38
      i -= 1
    }
    var result = Field25519()
    i = 0
    while i < 16 {
      result.limbs[i] = product[i]
      i += 1
    }
    result.normalize()
    return result
  }

  func inverted() -> Field25519 {
    var result = Field25519(one: true)
    let base = self
    var bit = 254
    while bit >= 0 {
      result = result * result
      // p - 2 = 2^255 - 21: bits 254...5 and bits 3, 1, and 0 are set.
      let set = bit >= 5 || bit == 3 || bit == 1 || bit == 0
      if set { result = result * base }
      bit -= 1
    }
    return result
  }

  static func conditionalSwap(_ lhs: inout Field25519, _ rhs: inout Field25519, _ swap: UInt64) {
    let mask = UInt64(truncatingIfNeeded: -Int64(swap))
    var index = 0
    while index < 16 {
      let difference = UInt64(bitPattern: lhs.limbs[index] ^ rhs.limbs[index]) & mask
      lhs.limbs[index] ^= Int64(bitPattern: difference)
      rhs.limbs[index] ^= Int64(bitPattern: difference)
      index += 1
    }
  }

  /// Selects one field element without branching on `select`.
  ///
  /// Both inputs own initialized 16-limb storage. The result receives a new
  /// initialized owner, no pointer escapes, and `select` must be zero or one.
  static func selecting(
    _ whenZero: Field25519,
    _ whenOne: Field25519,
    select: UInt64
  ) -> Field25519 {
    let mask = UInt64(0) &- select
    var result = Field25519()
    var index = 0
    while index < 16 {
      let zero = UInt64(bitPattern: whenZero.limbs[index]) & ~mask
      let one = UInt64(bitPattern: whenOne.limbs[index]) & mask
      result.limbs[index] = Int64(bitPattern: zero | one)
      index += 1
    }
    return result
  }

  private mutating func normalize() {
    // Radix carries use arithmetic shifts so secret-dependent values do not
    // select a branch. Three fixed passes bound carries after multiplication
    // and the final subtraction is selected from its borrow mask.
    var repeatCount = 0
    while repeatCount < 3 {
      var carry: Int64 = 0
      var index = 0
      while index < 15 {
        let value = limbs[index] + carry
        carry = value >> 16
        limbs[index] = value - carry * Self.base
        index += 1
      }
      let value = limbs[15] + carry
      carry = value >> 16
      limbs[15] = value - carry * Self.base
      limbs[0] += carry * 38
      repeatCount += 1
    }
    let modulus: [Int64] = [65_517] + [Int64](repeating: 65_535, count: 14) + [32_767]
    var borrow: UInt64 = 0
    var differences = [Int64](repeating: 0, count: 16)
    var index = 0
    while index < 16 {
      let difference = limbs[index] - modulus[index] - Int64(borrow)
      borrow = UInt64(bitPattern: difference) >> 63
      differences[index] = difference + Int64(borrow * UInt64(Self.base))
      index += 1
    }
    let selectSubtraction = UInt64(0) &- (UInt64(1) &- borrow)
    index = 0
    while index < 16 {
      let selected = UInt64(bitPattern: differences[index]) & selectSubtraction
      let original = UInt64(bitPattern: limbs[index]) & ~selectSubtraction
      limbs[index] = Int64(bitPattern: selected | original)
      index += 1
    }
  }
}
