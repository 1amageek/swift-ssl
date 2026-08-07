import SSLCore

/// Radix-2^51 field arithmetic specialized for the X25519 Montgomery ladder.
struct X25519FieldElement {
  private static let radix: UInt64 = 1 << 51
  private static let mask: UInt64 = Self.radix - 1
  private static let modulus0: UInt64 = Self.mask - 18

  private var limb0: UInt64
  private var limb1: UInt64
  private var limb2: UInt64
  private var limb3: UInt64
  private var limb4: UInt64

  init() {
    limb0 = 0
    limb1 = 0
    limb2 = 0
    limb3 = 0
    limb4 = 0
  }

  init(one: Bool) {
    limb0 = one ? 1 : 0
    limb1 = 0
    limb2 = 0
    limb3 = 0
    limb4 = 0
  }

  init(constant: UInt64) {
    limb0 = constant
    limb1 = 0
    limb2 = 0
    limb3 = 0
    limb4 = 0
  }

  @inline(__always)
  init(
    table: UnsafePointer<UInt64>,
    offset: Int
  ) {
    // Unsafe boundary invariants:
    // - The caller retains immutable storage for at least offset + 5 UInt64 limbs.
    // - Generated-table offsets are nonnegative and validated by the table dimensions.
    // - UInt64 pointer arithmetic preserves alignment and initialized element binding.
    // - The pointer is read synchronously and never stored or returned.
    limb0 = table.advanced(by: offset).pointee
    limb1 = table.advanced(by: offset + 1).pointee
    limb2 = table.advanced(by: offset + 2).pointee
    limb3 = table.advanced(by: offset + 3).pointee
    limb4 = table.advanced(by: offset + 4).pointee
  }

  init(bytes: Span<UInt8>) {
    let word0 = Self.loadLittleEndian(bytes, offset: 0)
    let word1 = Self.loadLittleEndian(bytes, offset: 8)
    let word2 = Self.loadLittleEndian(bytes, offset: 16)
    let word3 = Self.loadLittleEndian(bytes, offset: 24)
    limb0 = word0 & Self.mask
    limb1 = ((word0 >> 51) | (word1 << 13)) & Self.mask
    limb2 = ((word1 >> 38) | (word2 << 26)) & Self.mask
    limb3 = ((word2 >> 25) | (word3 << 39)) & Self.mask
    limb4 = (word3 >> 12) & Self.mask
  }

  var bytes: ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var destination = output.mutableSpan
    encode(into: &destination)
    return output
  }

  func encode(into destination: inout MutableSpan<UInt8>) {
    let value = canonicalized()
    value.encodeCanonical(into: &destination)
  }

  /// Writes a canonical encoding only when the field value is nonzero.
  ///
  /// This keeps caller-owned output transactional when X25519 rejects a
  /// low-order peer public key whose shared secret is the all-zero string.
  func encodeIfNonZero(into destination: inout MutableSpan<UInt8>) -> Bool {
    let value = canonicalized()
    let nonZero = value.limb0 | value.limb1 | value.limb2 | value.limb3 | value.limb4
    guard nonZero != 0 else { return false }
    value.encodeCanonical(into: &destination)
    return true
  }

  private func encodeCanonical(into destination: inout MutableSpan<UInt8>) {
    let value = self
    let word0 = value.limb0 | (value.limb1 << 51)
    let word1 = (value.limb1 >> 13) | (value.limb2 << 38)
    let word2 = (value.limb2 >> 26) | (value.limb3 << 25)
    let word3 = (value.limb3 >> 39) | (value.limb4 << 12)
    Self.storeLittleEndian(word0, into: &destination, offset: 0)
    Self.storeLittleEndian(word1, into: &destination, offset: 8)
    Self.storeLittleEndian(word2, into: &destination, offset: 16)
    Self.storeLittleEndian(word3, into: &destination, offset: 24)
  }

  private func canonicalized() -> Self {
    var value = self
    value.strongReduce()

    let difference0 = value.limb0 &- Self.modulus0
    var borrow = difference0 >> 63
    let candidate0 = difference0 & Self.mask
    let difference1 = value.limb1 &- Self.mask &- borrow
    borrow = difference1 >> 63
    let candidate1 = difference1 & Self.mask
    let difference2 = value.limb2 &- Self.mask &- borrow
    borrow = difference2 >> 63
    let candidate2 = difference2 & Self.mask
    let difference3 = value.limb3 &- Self.mask &- borrow
    borrow = difference3 >> 63
    let candidate3 = difference3 & Self.mask
    let difference4 = value.limb4 &- Self.mask &- borrow
    borrow = difference4 >> 63
    let candidate4 = difference4 & Self.mask

    let selectCandidate = UInt64(0) &- (UInt64(1) &- borrow)
    value.limb0 =
      (candidate0 & selectCandidate) | (value.limb0 & ~selectCandidate)
    value.limb1 =
      (candidate1 & selectCandidate) | (value.limb1 & ~selectCandidate)
    value.limb2 =
      (candidate2 & selectCandidate) | (value.limb2 & ~selectCandidate)
    value.limb3 =
      (candidate3 & selectCandidate) | (value.limb3 & ~selectCandidate)
    value.limb4 =
      (candidate4 & selectCandidate) | (value.limb4 & ~selectCandidate)
    return value
  }

  @inline(__always)
  static func + (lhs: Self, rhs: Self) -> Self {
    Self(
      limb0: lhs.limb0 &+ rhs.limb0,
      limb1: lhs.limb1 &+ rhs.limb1,
      limb2: lhs.limb2 &+ rhs.limb2,
      limb3: lhs.limb3 &+ rhs.limb3,
      limb4: lhs.limb4 &+ rhs.limb4
    )
  }

  @inline(__always)
  static func - (lhs: Self, rhs: Self) -> Self {
    Self(
      limb0: lhs.limb0 &+ 4 * Self.modulus0 &- rhs.limb0,
      limb1: lhs.limb1 &+ 4 * Self.mask &- rhs.limb1,
      limb2: lhs.limb2 &+ 4 * Self.mask &- rhs.limb2,
      limb3: lhs.limb3 &+ 4 * Self.mask &- rhs.limb3,
      limb4: lhs.limb4 &+ 4 * Self.mask &- rhs.limb4
    )
  }

  @inline(__always)
  static func * (lhs: Self, rhs: Self) -> Self {
    // Arithmetic range invariant:
    // - Input limbs are bounded below 2^54 between point-operation reductions.
    // - Each accumulator contains five products, including at most four
    //   factors scaled by 19, and therefore remains below 2^111.
    // - UInt128 cannot overflow. Wrapping addition expresses that proven
    //   bound to the optimizer and avoids a conditional trap after every
    //   product accumulation in the constant-time ladder.
    let accumulator0 =
      UInt128(lhs.limb0) * UInt128(rhs.limb0)
      &+ UInt128(lhs.limb1) * UInt128(rhs.limb4 &* 19)
      &+ UInt128(lhs.limb2) * UInt128(rhs.limb3 &* 19)
      &+ UInt128(lhs.limb3) * UInt128(rhs.limb2 &* 19)
      &+ UInt128(lhs.limb4) * UInt128(rhs.limb1 &* 19)
    let accumulator1 =
      UInt128(lhs.limb0) * UInt128(rhs.limb1)
      &+ UInt128(lhs.limb1) * UInt128(rhs.limb0)
      &+ UInt128(lhs.limb2) * UInt128(rhs.limb4 &* 19)
      &+ UInt128(lhs.limb3) * UInt128(rhs.limb3 &* 19)
      &+ UInt128(lhs.limb4) * UInt128(rhs.limb2 &* 19)
    let accumulator2 =
      UInt128(lhs.limb0) * UInt128(rhs.limb2)
      &+ UInt128(lhs.limb1) * UInt128(rhs.limb1)
      &+ UInt128(lhs.limb2) * UInt128(rhs.limb0)
      &+ UInt128(lhs.limb3) * UInt128(rhs.limb4 &* 19)
      &+ UInt128(lhs.limb4) * UInt128(rhs.limb3 &* 19)
    let accumulator3 =
      UInt128(lhs.limb0) * UInt128(rhs.limb3)
      &+ UInt128(lhs.limb1) * UInt128(rhs.limb2)
      &+ UInt128(lhs.limb2) * UInt128(rhs.limb1)
      &+ UInt128(lhs.limb3) * UInt128(rhs.limb0)
      &+ UInt128(lhs.limb4) * UInt128(rhs.limb4 &* 19)
    let accumulator4 =
      UInt128(lhs.limb0) * UInt128(rhs.limb4)
      &+ UInt128(lhs.limb1) * UInt128(rhs.limb3)
      &+ UInt128(lhs.limb2) * UInt128(rhs.limb2)
      &+ UInt128(lhs.limb3) * UInt128(rhs.limb1)
      &+ UInt128(lhs.limb4) * UInt128(rhs.limb0)

    return Self.reduce(accumulator0, accumulator1, accumulator2, accumulator3, accumulator4)
  }

  @inline(__always)
  func squared() -> Self {
    let accumulator0 =
      UInt128(limb0) * UInt128(limb0)
      &+ UInt128(limb1) * UInt128(limb4 &* 38)
      &+ UInt128(limb2) * UInt128(limb3 &* 38)
    let accumulator1 =
      UInt128(limb0) * UInt128(limb1 &* 2)
      &+ UInt128(limb2) * UInt128(limb4 &* 38)
      &+ UInt128(limb3) * UInt128(limb3 &* 19)
    let accumulator2 =
      UInt128(limb0) * UInt128(limb2 &* 2)
      &+ UInt128(limb1) * UInt128(limb1)
      &+ UInt128(limb3) * UInt128(limb4 &* 38)
    let accumulator3 =
      UInt128(limb0) * UInt128(limb3 &* 2)
      &+ UInt128(limb1) * UInt128(limb2 &* 2)
      &+ UInt128(limb4) * UInt128(limb4 &* 19)
    let accumulator4 =
      UInt128(limb0) * UInt128(limb4 &* 2)
      &+ UInt128(limb1) * UInt128(limb3 &* 2)
      &+ UInt128(limb2) * UInt128(limb2)

    return Self.reduce(accumulator0, accumulator1, accumulator2, accumulator3, accumulator4)
  }

  @inline(__always)
  func multiplied(bySmall scalar: UInt64) -> Self {
    return Self.reduce(
      UInt128(limb0) * UInt128(scalar),
      UInt128(limb1) * UInt128(scalar),
      UInt128(limb2) * UInt128(scalar),
      UInt128(limb3) * UInt128(scalar),
      UInt128(limb4) * UInt128(scalar)
    )
  }

  func inverted() -> Self {
    let z2 = squared()
    let z8 = z2.squared().squared()
    let z9 = z8 * self
    let z11 = z9 * z2
    let z2To5Minus1 = z11.squared() * z9
    let z2To10Minus1 = z2To5Minus1.squared(times: 5) * z2To5Minus1
    let z2To20Minus1 = z2To10Minus1.squared(times: 10) * z2To10Minus1
    let z2To40Minus1 = z2To20Minus1.squared(times: 20) * z2To20Minus1
    let z2To50Minus1 = z2To40Minus1.squared(times: 10) * z2To10Minus1
    let z2To100Minus1 = z2To50Minus1.squared(times: 50) * z2To50Minus1
    let z2To200Minus1 = z2To100Minus1.squared(times: 100) * z2To100Minus1
    let z2To250Minus1 = z2To200Minus1.squared(times: 50) * z2To50Minus1
    return z2To250Minus1.squared(times: 5) * z11
  }

  @inline(__always)
  static func conditionalSwap(
    _ lhs: inout Self,
    _ rhs: inout Self,
    _ swap: UInt64
  ) {
    let mask = UInt64(0) &- swap
    var difference = (lhs.limb0 ^ rhs.limb0) & mask
    lhs.limb0 ^= difference
    rhs.limb0 ^= difference
    difference = (lhs.limb1 ^ rhs.limb1) & mask
    lhs.limb1 ^= difference
    rhs.limb1 ^= difference
    difference = (lhs.limb2 ^ rhs.limb2) & mask
    lhs.limb2 ^= difference
    rhs.limb2 ^= difference
    difference = (lhs.limb3 ^ rhs.limb3) & mask
    lhs.limb3 ^= difference
    rhs.limb3 ^= difference
    difference = (lhs.limb4 ^ rhs.limb4) & mask
    lhs.limb4 ^= difference
    rhs.limb4 ^= difference
  }

  @inline(__always)
  static func selecting(
    _ whenZero: Self,
    _ whenOne: Self,
    select: UInt64
  ) -> Self {
    let selectionMask = UInt64(0) &- select
    return Self(
      limb0: whenZero.limb0 ^ ((whenZero.limb0 ^ whenOne.limb0) & selectionMask),
      limb1: whenZero.limb1 ^ ((whenZero.limb1 ^ whenOne.limb1) & selectionMask),
      limb2: whenZero.limb2 ^ ((whenZero.limb2 ^ whenOne.limb2) & selectionMask),
      limb3: whenZero.limb3 ^ ((whenZero.limb3 ^ whenOne.limb3) & selectionMask),
      limb4: whenZero.limb4 ^ ((whenZero.limb4 ^ whenOne.limb4) & selectionMask)
    )
  }

  @inline(__always)
  func negated() -> Self {
    // Subtraction accepts bounded lazy limbs, but a value may already contain
    // the four-modulus bias from a preceding subtraction. Canonicalizing here
    // prevents per-limb UInt64 underflow when negating that representation.
    Self() - canonicalized()
  }

  @inline(__always)
  func negatedAssumingBounded() -> Self {
    // The caller must prove that every limb is no larger than the
    // corresponding four-modulus subtraction bias. Fixed-base table values
    // are canonical, and multiplication/squaring reduce their result below
    // that bound. Keeping this unchecked operation internal avoids six full
    // carry passes in each fixed-base negation without weakening the public
    // field-element contract.
    Self() - self
  }

  @inline(__always)
  private init(
    limb0: UInt64,
    limb1: UInt64,
    limb2: UInt64,
    limb3: UInt64,
    limb4: UInt64
  ) {
    self.limb0 = limb0
    self.limb1 = limb1
    self.limb2 = limb2
    self.limb3 = limb3
    self.limb4 = limb4
  }

  @inline(__always)
  private static func reduce(
    _ accumulator0: UInt128,
    _ accumulator1: UInt128,
    _ accumulator2: UInt128,
    _ accumulator3: UInt128,
    _ accumulator4: UInt128
  ) -> Self {
    // The multiplication bounds above also prove every carry propagation is
    // below 2^128. Wrapping additions remove redundant overflow traps without
    // changing the field result.
    // Every carry is proven to fit in UInt64. Truncating at each boundary
    // communicates that bound to the optimizer, so ARM64 emits a 128-bit plus
    // 64-bit carry instead of extending a five-limb UInt128 dependency chain.
    let carry0 = UInt64(truncatingIfNeeded: accumulator0 >> 51)
    let reduced1 = accumulator1 &+ UInt128(carry0)
    let carry1 = UInt64(truncatingIfNeeded: reduced1 >> 51)
    let reduced2 = accumulator2 &+ UInt128(carry1)
    let carry2 = UInt64(truncatingIfNeeded: reduced2 >> 51)
    let reduced3 = accumulator3 &+ UInt128(carry2)
    let carry3 = UInt64(truncatingIfNeeded: reduced3 >> 51)
    let reduced4 = accumulator4 &+ UInt128(carry3)
    let carry4 = UInt64(truncatingIfNeeded: reduced4 >> 51)
    var reduced0 =
      (UInt64(truncatingIfNeeded: accumulator0) & Self.mask)
      &+ carry4 &* 19
    let final1 =
      (UInt64(truncatingIfNeeded: reduced1) & Self.mask)
      &+ (reduced0 >> 51)
    reduced0 &= Self.mask
    return Self(
      limb0: reduced0,
      limb1: final1,
      limb2: UInt64(truncatingIfNeeded: reduced2) & Self.mask,
      limb3: UInt64(truncatingIfNeeded: reduced3) & Self.mask,
      limb4: UInt64(truncatingIfNeeded: reduced4) & Self.mask
    )
  }

  @inline(__always)
  private func squared(times: Int) -> Self {
    var result = self
    var remaining = times
    while remaining > 0 {
      result = result.squared()
      remaining -= 1
    }
    return result
  }

  @inline(__always)
  private mutating func strongReduce() {
    carryPass()
    carryPass()
    carryPass()
    carryPass()
    carryPass()
    carryPass()
  }

  @inline(__always)
  private mutating func carryPass() {
    var carry = limb0 >> 51
    limb0 &= Self.mask
    limb1 &+= carry
    carry = limb1 >> 51
    limb1 &= Self.mask
    limb2 &+= carry
    carry = limb2 >> 51
    limb2 &= Self.mask
    limb3 &+= carry
    carry = limb3 >> 51
    limb3 &= Self.mask
    limb4 &+= carry
    carry = limb4 >> 51
    limb4 &= Self.mask
    limb0 &+= carry &* 19
  }

  @inline(__always)
  private static func loadLittleEndian(
    _ bytes: Span<UInt8>,
    offset: Int
  ) -> UInt64 {
    UInt64(bytes[unchecked: offset])
      | (UInt64(bytes[unchecked: offset + 1]) << 8)
      | (UInt64(bytes[unchecked: offset + 2]) << 16)
      | (UInt64(bytes[unchecked: offset + 3]) << 24)
      | (UInt64(bytes[unchecked: offset + 4]) << 32)
      | (UInt64(bytes[unchecked: offset + 5]) << 40)
      | (UInt64(bytes[unchecked: offset + 6]) << 48)
      | (UInt64(bytes[unchecked: offset + 7]) << 56)
  }

  @inline(__always)
  private static func storeLittleEndian(
    _ word: UInt64,
    into output: inout MutableSpan<UInt8>,
    offset: Int
  ) {
    output[unchecked: offset] = UInt8(truncatingIfNeeded: word)
    output[unchecked: offset + 1] = UInt8(truncatingIfNeeded: word >> 8)
    output[unchecked: offset + 2] = UInt8(truncatingIfNeeded: word >> 16)
    output[unchecked: offset + 3] = UInt8(truncatingIfNeeded: word >> 24)
    output[unchecked: offset + 4] = UInt8(truncatingIfNeeded: word >> 32)
    output[unchecked: offset + 5] = UInt8(truncatingIfNeeded: word >> 40)
    output[unchecked: offset + 6] = UInt8(truncatingIfNeeded: word >> 48)
    output[unchecked: offset + 7] = UInt8(truncatingIfNeeded: word >> 56)
  }
}
