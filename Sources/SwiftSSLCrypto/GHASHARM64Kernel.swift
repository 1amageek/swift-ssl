#if canImport(Darwin) && arch(arm64) && canImport(simd)
  import simd

  /// ARM64 carry-less multiplication for the GHASH field.
  ///
  /// Swift cannot import `vmull_p64` because Clang's `poly128_t` result is not
  /// representable in Swift. This kernel batches the equivalent recursive
  /// Karatsuba product into four importable `vmull_p8` operations. All values
  /// remain fixed-width stack or register storage; no pointer or allocation is
  /// involved.
  enum GHASHARM64Kernel {
    @inline(__always)
    static func multiply(
      xHigh: UInt64,
      xLow: UInt64,
      hashHigh: UInt64,
      hashLow: UInt64
    ) -> (UInt64, UInt64) {
      // GHASH numbers polynomial coefficients from the most-significant bit.
      // Reverse the complete bit string into the conventional little-endian
      // polynomial representation used by the carry-less product.
      let product = rawProduct(
        xHigh: xHigh,
        xLow: xLow,
        hashHigh: hashHigh,
        hashLow: hashLow
      )
      let reduced = reduce(product.0, product.1, product.2, product.3)
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    /// Evaluates four consecutive GHASH blocks with one final reduction.
    ///
    /// `hashPowers` stores H, H^2, H^3, and H^4 as high/low pairs. `blocks`
    /// stores X1 through X4 in the same layout. The aggregation is the exact
    /// field identity `(Y xor X1)H^4 xor X2H^3 xor X3H^2 xor X4H`.
    @inline(__always)
    static func multiplyFour(
      accumulatorHigh: UInt64,
      accumulatorLow: UInt64,
      blocks: SIMD8<UInt64>,
      hashPowers: SIMD8<UInt64>
    ) -> (UInt64, UInt64) {
      let product1 = rawProduct(
        xHigh: accumulatorHigh ^ blocks[0],
        xLow: accumulatorLow ^ blocks[1],
        hashHigh: hashPowers[6],
        hashLow: hashPowers[7]
      )
      let product2 = rawProduct(
        xHigh: blocks[2],
        xLow: blocks[3],
        hashHigh: hashPowers[4],
        hashLow: hashPowers[5]
      )
      let product3 = rawProduct(
        xHigh: blocks[4],
        xLow: blocks[5],
        hashHigh: hashPowers[2],
        hashLow: hashPowers[3]
      )
      let product4 = rawProduct(
        xHigh: blocks[6],
        xLow: blocks[7],
        hashHigh: hashPowers[0],
        hashLow: hashPowers[1]
      )
      let reduced = reduce(
        product1.0 ^ product2.0 ^ product3.0 ^ product4.0,
        product1.1 ^ product2.1 ^ product3.1 ^ product4.1,
        product1.2 ^ product2.2 ^ product3.2 ^ product4.2,
        product1.3 ^ product2.3 ^ product3.3 ^ product4.3
      )
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    @inline(__always)
    private static func rawProduct(
      xHigh: UInt64,
      xLow: UInt64,
      hashHigh: UInt64,
      hashLow: UInt64
    ) -> (UInt64, UInt64, UInt64, UInt64) {
      let x0 = reverseBits(xHigh)
      let x1 = reverseBits(xLow)
      let h0 = reverseBits(hashHigh)
      let h1 = reverseBits(hashLow)

      let product0 = carrylessMultiply64(x0, h0)
      let product1 = carrylessMultiply64(x1, h1)
      let productMiddle = carrylessMultiply64(x0 ^ x1, h0 ^ h1)
      let crossLow = productMiddle.0 ^ product0.0 ^ product1.0
      let crossHigh = productMiddle.1 ^ product0.1 ^ product1.1
      return (
        product0.0,
        product0.1 ^ crossLow,
        product1.0 ^ crossHigh,
        product1.1
      )
    }

    @inline(__always)
    private static func carrylessMultiply64(
      _ lhs: UInt64,
      _ rhs: UInt64
    ) -> (UInt64, UInt64) {
      let a0 = UInt16(truncatingIfNeeded: lhs)
      let a1 = UInt16(truncatingIfNeeded: lhs >> 16)
      let a2 = UInt16(truncatingIfNeeded: lhs >> 32)
      let a3 = UInt16(truncatingIfNeeded: lhs >> 48)
      let b0 = UInt16(truncatingIfNeeded: rhs)
      let b1 = UInt16(truncatingIfNeeded: rhs >> 16)
      let b2 = UInt16(truncatingIfNeeded: rhs >> 32)
      let b3 = UInt16(truncatingIfNeeded: rhs >> 48)

      let a01 = a0 ^ a1
      let a23 = a2 ^ a3
      let b01 = b0 ^ b1
      let b23 = b2 ^ b3
      let a02 = a0 ^ a2
      let a13 = a1 ^ a3
      let b02 = b0 ^ b2
      let b13 = b1 ^ b3

      let lhs0 = SIMD8<UInt8>(
        low(a0), high(a0), folded(a0),
        low(a1), high(a1), folded(a1),
        low(a01), high(a01)
      )
      let rhs0 = SIMD8<UInt8>(
        low(b0), high(b0), folded(b0),
        low(b1), high(b1), folded(b1),
        low(b01), high(b01)
      )
      let lhs1 = SIMD8<UInt8>(
        folded(a01),
        low(a2), high(a2), folded(a2),
        low(a3), high(a3), folded(a3),
        low(a23)
      )
      let rhs1 = SIMD8<UInt8>(
        folded(b01),
        low(b2), high(b2), folded(b2),
        low(b3), high(b3), folded(b3),
        low(b23)
      )
      let lhs2 = SIMD8<UInt8>(
        high(a23), folded(a23),
        low(a02), high(a02), folded(a02),
        low(a13), high(a13), folded(a13)
      )
      let rhs2 = SIMD8<UInt8>(
        high(b23), folded(b23),
        low(b02), high(b02), folded(b02),
        low(b13), high(b13), folded(b13)
      )
      let aMiddle = a02 ^ a13
      let bMiddle = b02 ^ b13
      let lhs3 = SIMD8<UInt8>(
        low(aMiddle), high(aMiddle), folded(aMiddle),
        0, 0, 0, 0, 0
      )
      let rhs3 = SIMD8<UInt8>(
        low(bMiddle), high(bMiddle), folded(bMiddle),
        0, 0, 0, 0, 0
      )

      let products0 = vmull_p8(lhs0, rhs0)
      let products1 = vmull_p8(lhs1, rhs1)
      let products2 = vmull_p8(lhs2, rhs2)
      let products3 = vmull_p8(lhs3, rhs3)

      let product00 = combine(products0[0], products0[1], products0[2])
      let product01 = combine(products0[3], products0[4], products0[5])
      let product0M = combine(products0[6], products0[7], products1[0])
      let product10 = combine(products1[1], products1[2], products1[3])
      let product11 = combine(products1[4], products1[5], products1[6])
      let product1M = combine(products1[7], products2[0], products2[1])
      let productM0 = combine(products2[2], products2[3], products2[4])
      let productM1 = combine(products2[5], products2[6], products2[7])
      let productMM = combine(products3[0], products3[1], products3[2])

      let lowProduct = combine32(product00, product01, product0M)
      let highProduct = combine32(product10, product11, product1M)
      let middleProduct = combine32(productM0, productM1, productMM)
      let cross = middleProduct ^ lowProduct ^ highProduct
      return (
        lowProduct ^ (cross << 32),
        highProduct ^ (cross >> 32)
      )
    }

    @inline(__always)
    private static func low(_ value: UInt16) -> UInt8 {
      UInt8(truncatingIfNeeded: value)
    }

    @inline(__always)
    private static func high(_ value: UInt16) -> UInt8 {
      UInt8(truncatingIfNeeded: value >> 8)
    }

    @inline(__always)
    private static func folded(_ value: UInt16) -> UInt8 {
      low(value) ^ high(value)
    }

    @inline(__always)
    private static func combine(
      _ lowProduct: UInt16,
      _ highProduct: UInt16,
      _ foldedProduct: UInt16
    ) -> UInt32 {
      let middle = lowProduct ^ highProduct ^ foldedProduct
      return UInt32(lowProduct)
        ^ (UInt32(middle) << 8)
        ^ (UInt32(highProduct) << 16)
    }

    @inline(__always)
    private static func combine32(
      _ lowProduct: UInt32,
      _ highProduct: UInt32,
      _ foldedProduct: UInt32
    ) -> UInt64 {
      let middle = lowProduct ^ highProduct ^ foldedProduct
      return UInt64(lowProduct)
        ^ (UInt64(middle) << 16)
        ^ (UInt64(highProduct) << 32)
    }

    @inline(__always)
    private static func reduce(
      _ word0: UInt64,
      _ word1: UInt64,
      _ word2: UInt64,
      _ word3: UInt64
    ) -> (UInt64, UInt64) {
      let first = multiplyByReductionPolynomial(word2)
      let second = multiplyByReductionPolynomial(word3)
      let overflow = multiplyByReductionPolynomial(second.1)
      return (
        word0 ^ first.0 ^ overflow.0,
        word1 ^ first.1 ^ second.0 ^ overflow.1
      )
    }

    @inline(__always)
    private static func multiplyByReductionPolynomial(
      _ value: UInt64
    ) -> (UInt64, UInt64) {
      (
        value ^ (value << 1) ^ (value << 2) ^ (value << 7),
        (value >> 63) ^ (value >> 62) ^ (value >> 57)
      )
    }

    @inline(__always)
    private static func reverseBits(_ value: UInt64) -> UInt64 {
      var value = value
      value =
        ((value & 0x5555_5555_5555_5555) << 1)
        | ((value >> 1) & 0x5555_5555_5555_5555)
      value =
        ((value & 0x3333_3333_3333_3333) << 2)
        | ((value >> 2) & 0x3333_3333_3333_3333)
      value =
        ((value & 0x0f0f_0f0f_0f0f_0f0f) << 4)
        | ((value >> 4) & 0x0f0f_0f0f_0f0f_0f0f)
      return value.byteSwapped
    }
  }
#endif
