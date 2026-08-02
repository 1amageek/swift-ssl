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
