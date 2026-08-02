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
      let directIndices = SIMD16<UInt8>(
        0, 2, 0, 4, 6, 4, 0, 2,
        1, 3, 1, 5, 7, 5, 1, 3
      )
      let xorIndices = SIMD16<UInt8>(
        0xff, 0xff, 2, 0xff, 0xff, 6, 4, 6,
        0xff, 0xff, 3, 0xff, 0xff, 7, 5, 7
      )
      let lhsBytes = vreinterpretq_u8_u64(SIMD2<UInt64>(repeating: lhs))
      let rhsBytes = vreinterpretq_u8_u64(SIMD2<UInt64>(repeating: rhs))
      let lhsParts =
        vqtbl1q_u8(lhsBytes, directIndices)
        ^ vqtbl1q_u8(lhsBytes, xorIndices)
      let rhsParts =
        vqtbl1q_u8(rhsBytes, directIndices)
        ^ vqtbl1q_u8(rhsBytes, xorIndices)
      let lhsLow = vget_low_u8(lhsParts)
      let lhsHigh = vget_high_u8(lhsParts)
      let rhsLow = vget_low_u8(rhsParts)
      let rhsHigh = vget_high_u8(rhsParts)
      let lowProducts = vmull_p8(lhsLow, rhsLow)
      let highProducts = vmull_p8(lhsHigh, rhsHigh)
      let foldedProducts = vmull_p8(lhsLow ^ lhsHigh, rhsLow ^ rhsHigh)
      let lhsMiddle = UInt16(
        truncatingIfNeeded: lhs ^ (lhs >> 16) ^ (lhs >> 32) ^ (lhs >> 48)
      )
      let rhsMiddle = UInt16(
        truncatingIfNeeded: rhs ^ (rhs >> 16) ^ (rhs >> 32) ^ (rhs >> 48)
      )
      let middleProducts = vmull_p8(
        SIMD8(low(lhsMiddle), high(lhsMiddle), folded(lhsMiddle), 0, 0, 0, 0, 0),
        SIMD8(low(rhsMiddle), high(rhsMiddle), folded(rhsMiddle), 0, 0, 0, 0, 0)
      )

      let product00 = combine(lowProducts[0], highProducts[0], foldedProducts[0])
      let product01 = combine(lowProducts[1], highProducts[1], foldedProducts[1])
      let product0M = combine(lowProducts[2], highProducts[2], foldedProducts[2])
      let product10 = combine(lowProducts[3], highProducts[3], foldedProducts[3])
      let product11 = combine(lowProducts[4], highProducts[4], foldedProducts[4])
      let product1M = combine(lowProducts[5], highProducts[5], foldedProducts[5])
      let productM0 = combine(lowProducts[6], highProducts[6], foldedProducts[6])
      let productM1 = combine(lowProducts[7], highProducts[7], foldedProducts[7])
      let productMM = combine(middleProducts[0], middleProducts[1], middleProducts[2])

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
