#if canImport(Darwin) && arch(arm64) && canImport(simd)
  import Builtin
  import simd

  /// ARM64 carry-less multiplication for the GHASH field.
  ///
  /// Swift cannot import `vmull_p64` because Clang's `poly128_t` result is not
  /// representable in Swift. The pinned Swift 6.4 toolchain exposes the same
  /// LLVM operation through `BuiltinModule`, keeping the polynomial product in
  /// fixed-width Swift storage without a C, assembly, or allocation boundary.
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
      let product = rawProductReversed(
        x0: reverseBits(xHigh),
        x1: reverseBits(xLow),
        h0: reverseBits(hashHigh),
        h1: reverseBits(hashLow)
      )
      let reduced = reduce(product.0, product.1, product.2, product.3)
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    /// Precomputes H, H^2, H^3, and H^4 in the representation consumed by
    /// the ARM64 kernel. Keeping these immutable powers reversed avoids
    /// repeating the same bit-order conversion for every message block.
    @inline(__always)
    static func makeReversedHashPowers(
      hashHigh: UInt64,
      hashLow: UInt64
    ) -> SIMD8<UInt64> {
      let h0 = reverseBits(hashHigh)
      let h1 = reverseBits(hashLow)
      let squaredProduct = rawProductReversed(x0: h0, x1: h1, h0: h0, h1: h1)
      let squared = reduce(
        squaredProduct.0,
        squaredProduct.1,
        squaredProduct.2,
        squaredProduct.3
      )
      let cubedProduct = rawProductReversed(
        x0: squared.0,
        x1: squared.1,
        h0: h0,
        h1: h1
      )
      let cubed = reduce(
        cubedProduct.0,
        cubedProduct.1,
        cubedProduct.2,
        cubedProduct.3
      )
      let fourthProduct = rawProductReversed(
        x0: squared.0,
        x1: squared.1,
        h0: squared.0,
        h1: squared.1
      )
      let fourth = reduce(
        fourthProduct.0,
        fourthProduct.1,
        fourthProduct.2,
        fourthProduct.3
      )
      return SIMD8(h0, h1, squared.0, squared.1, cubed.0, cubed.1, fourth.0, fourth.1)
    }

    /// Extends H through H^4 to H through H^8 in reversed polynomial order.
    ///
    /// This work is performed only for messages large enough to recover its
    /// four field multiplications by eliminating more GHASH reductions.
    @inline(__always)
    static func makeEightReversedHashPowers(
      _ firstFour: SIMD8<UInt64>
    ) -> SIMD16<UInt64> {
      let fifthProduct = rawProductReversed(
        x0: firstFour[6],
        x1: firstFour[7],
        h0: firstFour[0],
        h1: firstFour[1]
      )
      let fifth = reduce(
        fifthProduct.0,
        fifthProduct.1,
        fifthProduct.2,
        fifthProduct.3
      )
      let sixthProduct = rawProductReversed(
        x0: firstFour[6],
        x1: firstFour[7],
        h0: firstFour[2],
        h1: firstFour[3]
      )
      let sixth = reduce(
        sixthProduct.0,
        sixthProduct.1,
        sixthProduct.2,
        sixthProduct.3
      )
      let seventhProduct = rawProductReversed(
        x0: firstFour[6],
        x1: firstFour[7],
        h0: firstFour[4],
        h1: firstFour[5]
      )
      let seventh = reduce(
        seventhProduct.0,
        seventhProduct.1,
        seventhProduct.2,
        seventhProduct.3
      )
      let eighthProduct = rawProductReversed(
        x0: firstFour[6],
        x1: firstFour[7],
        h0: firstFour[6],
        h1: firstFour[7]
      )
      let eighth = reduce(
        eighthProduct.0,
        eighthProduct.1,
        eighthProduct.2,
        eighthProduct.3
      )
      return SIMD16(
        firstFour[0], firstFour[1],
        firstFour[2], firstFour[3],
        firstFour[4], firstFour[5],
        firstFour[6], firstFour[7],
        fifth.0, fifth.1,
        sixth.0, sixth.1,
        seventh.0, seventh.1,
        eighth.0, eighth.1
      )
    }

    @inline(__always)
    static func multiplyWithReversedHash(
      xHigh: UInt64,
      xLow: UInt64,
      reversedHash0: UInt64,
      reversedHash1: UInt64
    ) -> (UInt64, UInt64) {
      let product = rawProductReversed(
        x0: reverseBits(xHigh),
        x1: reverseBits(xLow),
        h0: reversedHash0,
        h1: reversedHash1
      )
      let reduced = reduce(product.0, product.1, product.2, product.3)
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    /// Evaluates four consecutive GHASH blocks with one final reduction.
    ///
    /// `reversedHashPowers` stores H, H^2, H^3, and H^4 as reversed low/high
    /// polynomial limbs. `blocks` stores X1 through X4 in network byte order.
    /// The aggregation is the exact field identity
    /// `(Y xor X1)H^4 xor X2H^3 xor X3H^2 xor X4H`.
    @inline(__always)
    static func multiplyFour(
      accumulatorHigh: UInt64,
      accumulatorLow: UInt64,
      blocks: SIMD8<UInt64>,
      reversedHashPowers: SIMD8<UInt64>
    ) -> (UInt64, UInt64) {
      let product1 = rawProductReversed(
        x0: reverseBits(accumulatorHigh ^ blocks[0]),
        x1: reverseBits(accumulatorLow ^ blocks[1]),
        h0: reversedHashPowers[6],
        h1: reversedHashPowers[7]
      )
      let product2 = rawProductReversed(
        x0: reverseBits(blocks[2]),
        x1: reverseBits(blocks[3]),
        h0: reversedHashPowers[4],
        h1: reversedHashPowers[5]
      )
      let product3 = rawProductReversed(
        x0: reverseBits(blocks[4]),
        x1: reverseBits(blocks[5]),
        h0: reversedHashPowers[2],
        h1: reversedHashPowers[3]
      )
      let product4 = rawProductReversed(
        x0: reverseBits(blocks[6]),
        x1: reverseBits(blocks[7]),
        h0: reversedHashPowers[0],
        h1: reversedHashPowers[1]
      )
      let reduced = reduce(
        product1.0 ^ product2.0 ^ product3.0 ^ product4.0,
        product1.1 ^ product2.1 ^ product3.1 ^ product4.1,
        product1.2 ^ product2.2 ^ product3.2 ^ product4.2,
        product1.3 ^ product2.3 ^ product3.3 ^ product4.3
      )
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    /// Evaluates eight consecutive GHASH blocks with one final reduction.
    ///
    /// `reversedHashPowers` stores H through H^8 as reversed low/high limbs.
    /// The aggregation applies `(Y xor X1)H^8` through `X8H` exactly once.
    @inline(__always)
    static func multiplyEight(
      accumulatorHigh: UInt64,
      accumulatorLow: UInt64,
      blocks: SIMD16<UInt64>,
      reversedHashPowers: SIMD16<UInt64>
    ) -> (UInt64, UInt64) {
      let product1 = rawProductReversed(
        x0: reverseBits(accumulatorHigh ^ blocks[0]),
        x1: reverseBits(accumulatorLow ^ blocks[1]),
        h0: reversedHashPowers[14],
        h1: reversedHashPowers[15]
      )
      let product2 = rawProductReversed(
        x0: reverseBits(blocks[2]),
        x1: reverseBits(blocks[3]),
        h0: reversedHashPowers[12],
        h1: reversedHashPowers[13]
      )
      let product3 = rawProductReversed(
        x0: reverseBits(blocks[4]),
        x1: reverseBits(blocks[5]),
        h0: reversedHashPowers[10],
        h1: reversedHashPowers[11]
      )
      let product4 = rawProductReversed(
        x0: reverseBits(blocks[6]),
        x1: reverseBits(blocks[7]),
        h0: reversedHashPowers[8],
        h1: reversedHashPowers[9]
      )
      let product5 = rawProductReversed(
        x0: reverseBits(blocks[8]),
        x1: reverseBits(blocks[9]),
        h0: reversedHashPowers[6],
        h1: reversedHashPowers[7]
      )
      let product6 = rawProductReversed(
        x0: reverseBits(blocks[10]),
        x1: reverseBits(blocks[11]),
        h0: reversedHashPowers[4],
        h1: reversedHashPowers[5]
      )
      let product7 = rawProductReversed(
        x0: reverseBits(blocks[12]),
        x1: reverseBits(blocks[13]),
        h0: reversedHashPowers[2],
        h1: reversedHashPowers[3]
      )
      let product8 = rawProductReversed(
        x0: reverseBits(blocks[14]),
        x1: reverseBits(blocks[15]),
        h0: reversedHashPowers[0],
        h1: reversedHashPowers[1]
      )
      let reduced = reduce(
        product1.0 ^ product2.0 ^ product3.0 ^ product4.0
          ^ product5.0 ^ product6.0 ^ product7.0 ^ product8.0,
        product1.1 ^ product2.1 ^ product3.1 ^ product4.1
          ^ product5.1 ^ product6.1 ^ product7.1 ^ product8.1,
        product1.2 ^ product2.2 ^ product3.2 ^ product4.2
          ^ product5.2 ^ product6.2 ^ product7.2 ^ product8.2,
        product1.3 ^ product2.3 ^ product3.3 ^ product4.3
          ^ product5.3 ^ product6.3 ^ product7.3 ^ product8.3
      )
      return (reverseBits(reduced.0), reverseBits(reduced.1))
    }

    @inline(__always)
    private static func rawProductReversed(
      x0: UInt64,
      x1: UInt64,
      h0: UInt64,
      h1: UInt64
    ) -> (UInt64, UInt64, UInt64, UInt64) {
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
      // Builtin boundary invariants:
      // - Both UInt64 operands are fully initialized scalar values.
      // - The intrinsic returns all 128 initialized product bits in little-
      //   endian low/high limb order, matching SIMD2<UInt64> on Apple ARM64.
      // - No pointer, alias, borrow, or mutable storage escapes this function.
      let product = Builtin.int_aarch64_neon_pmull64(lhs._value, rhs._value)
      var bytes = SIMD16<UInt8>(repeating: 0)
      bytes._storage._value = product
      let words = vreinterpretq_u64_u8(bytes)
      return (words[0], words[1])
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
