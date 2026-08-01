import SwiftSSLCore

/// Constant-time Ed25519 fixed-base multiplication mapped to Montgomery u.
enum X25519FixedBase {
  static func scalarMultiply(scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: X25519PublicKey.byteCount)
    var destination = output.mutableSpan
    scalarMultiply(scalar: scalar, into: &destination)
    return output
  }

  static func scalarMultiply(
    scalar: Span<UInt8>,
    into destination: inout MutableSpan<UInt8>
  ) {
    X25519BasepointTable.limbs.withUnsafeBufferPointer { table in
      // Unsafe boundary invariants:
      // - The temporary allocation contains exactly 64 initialized Int8 digits.
      // - Every digit is in -8...8 after radix-16 recoding.
      // - The pointer and its buffer never escape this synchronous closure.
      // - The entire secret-dependent table lookup scans all eight candidates.
      // - The table is immutable and retained for the duration of this borrow.
      // - The digit storage is erased before the temporary allocation expires.
      // The generated table has exactly 3,840 limbs. All lookup offsets
      // below are bounded by 32 positions, 8 candidates, and 15 limbs.
      let tableBase = table.baseAddress!
      withUnsafeTemporaryAllocation(of: Int8.self, capacity: 64) { digits in
        defer {
          if let baseAddress = digits.baseAddress {
            SecureWipe.erase(
              UnsafeMutableRawPointer(baseAddress),
              byteCount: digits.count * MemoryLayout<Int8>.stride
            )
          }
        }

        var byteIndex = 0
        while byteIndex < 32 {
          let byte = scalar[unchecked: byteIndex]
          digits[byteIndex * 2] = Int8(byte & 15)
          digits[byteIndex * 2 + 1] = Int8(byte >> 4)
          byteIndex += 1
        }
        digits[0] &= 8
        digits[63] = (digits[63] & 3) | 4

        var carry: Int16 = 0
        var digitIndex = 0
        while digitIndex < 63 {
          let value = Int16(digits[digitIndex]) + carry
          carry = (value + 8) >> 4
          digits[digitIndex] = Int8(value - (carry << 4))
          digitIndex += 1
        }
        digits[63] += Int8(carry)

        var point = X25519ExtendedPoint.identity
        digitIndex = 1
        while digitIndex < 64 {
          point = point.adding(
            select(
              position: digitIndex >> 1,
              digit: digits[digitIndex],
              table: tableBase
            )
          )
          digitIndex += 2
        }

        point = point.doubled()
        point = point.doubled()
        point = point.doubled()
        point = point.doubled()

        digitIndex = 0
        while digitIndex < 64 {
          point = point.adding(
            select(
              position: digitIndex >> 1,
              digit: digits[digitIndex],
              table: tableBase
            )
          )
          digitIndex += 2
        }

        point.montgomeryUCoordinate.encode(into: &destination)
      }
    }
  }

  @inline(__always)
  private static func select(
    position: Int,
    digit: Int8,
    table: UnsafePointer<UInt64>
  ) -> X25519PrecomputedPoint {
    let bitPattern = UInt8(bitPattern: digit)
    let isNegative = UInt64(bitPattern >> 7)
    let negativeMask = UInt8(0) &- UInt8(isNegative)
    let absoluteDigit = (bitPattern ^ negativeMask) &+ UInt8(isNegative)

    var selected = X25519PrecomputedPoint.identity
    var candidateIndex = 0
    while candidateIndex < 8 {
      let candidate = X25519PrecomputedPoint(
        table: table,
        offset: ((position * 8) + candidateIndex) * 15
      )
      let choose = constantTimeEqual(
        absoluteDigit,
        UInt8(candidateIndex + 1)
      )
      selected = X25519PrecomputedPoint.selecting(
        selected,
        candidate,
        select: choose
      )
      candidateIndex += 1
    }

    let negative = X25519PrecomputedPoint(
      yPlusX: selected.yMinusX,
      yMinusX: selected.yPlusX,
      xyTwoD: selected.xyTwoD.negated()
    )
    return X25519PrecomputedPoint.selecting(
      selected,
      negative,
      select: isNegative
    )
  }

  @inline(__always)
  private static func constantTimeEqual(_ lhs: UInt8, _ rhs: UInt8) -> UInt64 {
    let difference = UInt64(lhs ^ rhs)
    return ((difference | (UInt64(0) &- difference)) >> 63) ^ 1
  }
}

private struct X25519PrecomputedPoint {
  let yPlusX: X25519FieldElement
  let yMinusX: X25519FieldElement
  let xyTwoD: X25519FieldElement

  static let identity = Self(
    yPlusX: X25519FieldElement(one: true),
    yMinusX: X25519FieldElement(one: true),
    xyTwoD: X25519FieldElement()
  )

  @inline(__always)
  init(
    yPlusX: X25519FieldElement,
    yMinusX: X25519FieldElement,
    xyTwoD: X25519FieldElement
  ) {
    self.yPlusX = yPlusX
    self.yMinusX = yMinusX
    self.xyTwoD = xyTwoD
  }

  @inline(__always)
  init(
    table: UnsafePointer<UInt64>,
    offset: Int
  ) {
    yPlusX = X25519FieldElement(table: table, offset: offset)
    yMinusX = X25519FieldElement(table: table, offset: offset + 5)
    xyTwoD = X25519FieldElement(table: table, offset: offset + 10)
  }

  @inline(__always)
  static func selecting(
    _ whenZero: Self,
    _ whenOne: Self,
    select: UInt64
  ) -> Self {
    Self(
      yPlusX: X25519FieldElement.selecting(
        whenZero.yPlusX,
        whenOne.yPlusX,
        select: select
      ),
      yMinusX: X25519FieldElement.selecting(
        whenZero.yMinusX,
        whenOne.yMinusX,
        select: select
      ),
      xyTwoD: X25519FieldElement.selecting(
        whenZero.xyTwoD,
        whenOne.xyTwoD,
        select: select
      )
    )
  }
}

private struct X25519ExtendedPoint {
  let x: X25519FieldElement
  let y: X25519FieldElement
  let z: X25519FieldElement
  let t: X25519FieldElement

  static let identity = Self(
    x: X25519FieldElement(),
    y: X25519FieldElement(one: true),
    z: X25519FieldElement(one: true),
    t: X25519FieldElement()
  )

  @inline(__always)
  func adding(_ other: X25519PrecomputedPoint) -> Self {
    let yPlusX = y + x
    let yMinusX = y - x
    let productPlus = yPlusX * other.yPlusX
    let productMinus = yMinusX * other.yMinusX
    let productT = t * other.xyTwoD
    let doubledZ = z + z
    let completedX = productPlus - productMinus
    let completedY = productPlus + productMinus
    let completedZ = doubledZ + productT
    let completedT = doubledZ - productT
    return Self(
      x: completedX * completedT,
      y: completedY * completedZ,
      z: completedZ * completedT,
      t: completedX * completedY
    )
  }

  @inline(__always)
  func doubled() -> Self {
    let xx = x.squared()
    let yy = y.squared()
    let zzTwo = z.squared().multiplied(bySmall: 2)
    let negativeXX = xx.negated()
    let xy = (x + y).squared() - xx - yy
    let yMinusX = negativeXX + yy
    let zDifference = yMinusX - zzTwo
    let negativeSum = negativeXX - yy
    return Self(
      x: xy * zDifference,
      y: yMinusX * negativeSum,
      z: zDifference * yMinusX,
      t: xy * negativeSum
    )
  }

  var montgomeryUCoordinate: X25519FieldElement {
    let numerator = z + y
    let denominator = z - y
    return numerator * denominator.inverted()
  }
}
