import SwiftSSLCore

#if os(macOS) && arch(arm64) && canImport(simd)
  import simd
#endif

enum MLKEMArithmetic {
  typealias Coefficient = UInt16

  static let modulus: Coefficient = 3_329

  // Hot arithmetic uses wrapping UInt32 operations only after coefficients have
  // been canonicalized to 0..<modulus. Debug assertions preserve the range proof;
  // the largest intermediate is below 2 * modulus * modulus + modulus.

  private static let zetas: ContiguousArray<Coefficient> = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
  ]

  private static let modRoots: ContiguousArray<Coefficient> = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680,
    1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662, 667, 3281, 48, 233, 3096,
    756, 2573, 2156, 1173, 3015, 314, 3050, 279,
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
    1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
    939, 2390, 2308, 1021, 2437, 892, 2388, 941,
    733, 2596, 2337, 992, 268, 3061, 641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572,
    2099, 1230, 561, 2768, 2466, 863, 2594, 735,
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
    1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
  ]

  @inline(__always)
  static func reduce(_ value: Int64) -> Coefficient {
    let remainder = Int32(value % Int64(modulus))
    return Coefficient(
      truncatingIfNeeded: remainder + ((remainder >> 31) & Int32(modulus))
    )
  }

  @inline(__always)
  static func add(_ lhs: Coefficient, _ rhs: Coefficient) -> Coefficient {
    reduceOnce(lhs &+ rhs)
  }

  @inline(__always)
  static func subtract(_ lhs: Coefficient, _ rhs: Coefficient) -> Coefficient {
    reduceOnce(lhs &+ modulus &- rhs)
  }

  @inline(__always)
  private static func reduceOnce(_ value: Coefficient) -> Coefficient {
    assert(value < 2 * modulus)
    #if os(macOS) && arch(arm64) && canImport(simd)
      // The pinned Swift 6.4 ARM64 compiler lowers this form to one `sub` and
      // one branch-free unsigned `umin` per NEON vector. The bitwise form below
      // remains the target-independent constant-time contract.
      return Swift.min(value, value &- modulus)
    #else
      let subtracted = value &- modulus
      let mask = Coefficient.zero &- (subtracted >> 15)
      return (mask & value) | (~mask & subtracted)
    #endif
  }

  @inline(__always)
  private static func reducePositive(_ value: UInt32) -> Coefficient {
    assert(value < UInt32(modulus) + 2 * UInt32(modulus) * UInt32(modulus))
    let quotient = UInt32((UInt64(value) * 5_039) >> 24)
    return reduceOnce(
      Coefficient(truncatingIfNeeded: value &- (quotient &* UInt32(modulus)))
    )
  }

  @inline(__always)
  private static func multiplyReduced(_ lhs: Coefficient, _ rhs: Coefficient) -> Coefficient {
    reducePositive(UInt32(lhs) &* UInt32(rhs))
  }

  static func forwardNTT(_ polynomial: inout MutableSpan<Coefficient>) {
    precondition(polynomial.count == MLKEMPolynomialStorage.coefficientCount)
    // Unsafe boundary invariants:
    // - The validated span owns exactly 256 initialized coefficients.
    // - Every stage index is statically bounded by 0..<256.
    // - The pointer remains inside this synchronous exclusive borrow.
    polynomial.withUnsafeMutableBufferPointer { buffer in
      let pointer = buffer.baseAddress.unsafelyUnwrapped
      forwardNTTStage(pointer, step: 1, offset: 128)
      forwardNTTStage(pointer, step: 2, offset: 64)
      forwardNTTStage(pointer, step: 4, offset: 32)
      forwardNTTStage(pointer, step: 8, offset: 16)
      forwardNTTStage(pointer, step: 16, offset: 8)
      forwardNTTStage(pointer, step: 32, offset: 4)
      forwardNTTStage(pointer, step: 64, offset: 2)
    }
  }

  static func inverseNTT(_ polynomial: inout MutableSpan<Coefficient>) {
    precondition(polynomial.count == MLKEMPolynomialStorage.coefficientCount)
    // Unsafe boundary invariants match forwardNTT; all accesses remain within
    // the validated 256-element owner and the pointer cannot escape.
    polynomial.withUnsafeMutableBufferPointer { buffer in
      let pointer = buffer.baseAddress.unsafelyUnwrapped
      inverseNTTStages(pointer)

      var index = 0
      while index < 256 {
        pointer[index] = multiplyReduced(pointer[index], 3_303)
        index += 1
      }
    }
  }

  static func inverseNTT(
    _ polynomial: inout MutableSpan<Coefficient>,
    adding addend: Span<Coefficient>
  ) {
    precondition(polynomial.count == MLKEMPolynomialStorage.coefficientCount)
    precondition(addend.count == MLKEMPolynomialStorage.coefficientCount)
    // Unsafe boundary invariants:
    // - Both spans contain exactly 256 initialized coefficients.
    // - The caller provides distinct owners for addend and polynomial.
    // - Every access stays in bounds and neither pointer escapes this borrow.
    addend.withUnsafeBufferPointer { addendBuffer in
      polynomial.withUnsafeMutableBufferPointer { polynomialBuffer in
        let addendPointer = addendBuffer.baseAddress.unsafelyUnwrapped
        let polynomialPointer = polynomialBuffer.baseAddress.unsafelyUnwrapped
        inverseNTTStages(polynomialPointer)

        var index = 0
        while index < 256 {
          polynomialPointer[index] = add(
            multiplyReduced(polynomialPointer[index], 3_303),
            addendPointer[index]
          )
          index += 1
        }
      }
    }
  }

  @inline(__always)
  private static func forwardNTTStage(
    _ polynomial: UnsafeMutablePointer<Coefficient>,
    step: Int,
    offset: Int
  ) {
    var group = 0
    var start = 0
    while group < step {
      let zeta = zetas[step + group]
      let end = start + offset
      var index = start
      while index < end {
        let product = multiplyReduced(zeta, polynomial[index + offset])
        let value = polynomial[index]
        polynomial[index + offset] = subtract(value, product)
        polynomial[index] = add(value, product)
        index += 1
      }
      group += 1
      start += 2 * offset
    }
  }

  @inline(__always)
  private static func inverseNTTStage(
    _ polynomial: UnsafeMutablePointer<Coefficient>,
    step: Int,
    offset: Int
  ) {
    var group = 0
    var start = 0
    while group < step {
      let zeta = zetas[2 * step - 1 - group]
      let end = start + offset
      var index = start
      while index < end {
        let value = polynomial[index]
        polynomial[index] = add(value, polynomial[index + offset])
        polynomial[index + offset] = multiplyReduced(
          zeta,
          subtract(polynomial[index + offset], value)
        )
        index += 1
      }
      group += 1
      start += 2 * offset
    }
  }

  @inline(__always)
  private static func inverseNTTStages(
    _ polynomial: UnsafeMutablePointer<Coefficient>
  ) {
    inverseNTTStage(polynomial, step: 64, offset: 2)
    inverseNTTStage(polynomial, step: 32, offset: 4)
    inverseNTTStage(polynomial, step: 16, offset: 8)
    inverseNTTStage(polynomial, step: 8, offset: 16)
    inverseNTTStage(polynomial, step: 4, offset: 32)
    inverseNTTStage(polynomial, step: 2, offset: 64)
    inverseNTTStage(polynomial, step: 1, offset: 128)
  }

  static func multiplyNTTs(
    _ lhs: Span<Coefficient>,
    _ rhs: Span<Coefficient>,
    accumulatingInto output: inout MutableSpan<Coefficient>,
    initialize: Bool
  ) {
    precondition(lhs.count == 256 && rhs.count == 256 && output.count == 256)
    // Unsafe boundary invariants:
    // - All three spans contain exactly 256 initialized coefficients.
    // - The output owner is exclusively borrowed and does not overlap either input.
    // - Each pair accesses only base and base + 1 for base in 0...254.
    // - No borrowed pointer escapes these synchronous closures.
    lhs.withUnsafeBufferPointer { lhsBuffer in
      rhs.withUnsafeBufferPointer { rhsBuffer in
        output.withUnsafeMutableBufferPointer { outputBuffer in
          let lhsPointer = lhsBuffer.baseAddress.unsafelyUnwrapped
          let rhsPointer = rhsBuffer.baseAddress.unsafelyUnwrapped
          let outputPointer = outputBuffer.baseAddress.unsafelyUnwrapped
          if initialize {
            var pair = 0
            while pair < 128 {
              let base = pair * 2
              let product = multiplyNTTPair(
                lhsPointer,
                rhsPointer,
                base: base,
                gamma: modRoots[pair]
              )
              outputPointer[base] = product.0
              outputPointer[base + 1] = product.1
              pair += 1
            }
          } else {
            var pair = 0
            while pair < 128 {
              let base = pair * 2
              let product = multiplyNTTPairAccumulating(
                lhsPointer,
                rhsPointer,
                base: base,
                gamma: modRoots[pair],
                currentReal: outputPointer[base],
                currentImaginary: outputPointer[base + 1]
              )
              outputPointer[base] = product.0
              outputPointer[base + 1] = product.1
              pair += 1
            }
          }
        }
      }
    }
  }

  @inline(__always)
  private static func multiplyNTTPair(
    _ lhs: UnsafePointer<Coefficient>,
    _ rhs: UnsafePointer<Coefficient>,
    base: Int,
    gamma: Coefficient
  ) -> (Coefficient, Coefficient) {
    let realReal = UInt32(lhs[base]) &* UInt32(rhs[base])
    let imaginary = multiplyReduced(lhs[base + 1], rhs[base + 1])
    return (
      reducePositive(realReal &+ (UInt32(imaginary) &* UInt32(gamma))),
      reducePositive(
        (UInt32(lhs[base]) &* UInt32(rhs[base + 1]))
          &+ (UInt32(lhs[base + 1]) &* UInt32(rhs[base]))
      )
    )
  }

  @inline(__always)
  private static func multiplyNTTPairAccumulating(
    _ lhs: UnsafePointer<Coefficient>,
    _ rhs: UnsafePointer<Coefficient>,
    base: Int,
    gamma: Coefficient,
    currentReal: Coefficient,
    currentImaginary: Coefficient
  ) -> (Coefficient, Coefficient) {
    // Each accumulated expression remains below q + 2*q*q, so one Barrett
    // reduction is equivalent to reducing the product and then adding the
    // canonical prior value. This removes two redundant reduce-once passes.
    let realReal = UInt32(lhs[base]) &* UInt32(rhs[base])
    let imaginary = multiplyReduced(lhs[base + 1], rhs[base + 1])
    return (
      reducePositive(
        realReal &+ (UInt32(imaginary) &* UInt32(gamma)) &+ UInt32(currentReal)
      ),
      reducePositive(
        (UInt32(lhs[base]) &* UInt32(rhs[base + 1]))
          &+ (UInt32(lhs[base + 1]) &* UInt32(rhs[base]))
          &+ UInt32(currentImaginary)
      )
    )
  }

  static func add(
    _ addend: Span<Coefficient>,
    into output: inout MutableSpan<Coefficient>
  ) {
    precondition(addend.count == 256 && output.count == 256)
    // Both buffers contain 256 initialized coefficients, do not overlap,
    // and remain scoped to these synchronous borrows.
    addend.withUnsafeBufferPointer { addendBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let addendPointer = addendBuffer.baseAddress.unsafelyUnwrapped
        let outputPointer = outputBuffer.baseAddress.unsafelyUnwrapped
        var index = 0
        while index < 256 {
          outputPointer[index] = add(outputPointer[index], addendPointer[index])
          index += 1
        }
      }
    }
  }

  static func subtract(
    _ subtrahend: Span<Coefficient>,
    from output: inout MutableSpan<Coefficient>
  ) {
    precondition(subtrahend.count == 256 && output.count == 256)
    // The validated nonoverlapping buffer and borrow invariants match add.
    subtrahend.withUnsafeBufferPointer { subtrahendBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let subtrahendPointer = subtrahendBuffer.baseAddress.unsafelyUnwrapped
        let outputPointer = outputBuffer.baseAddress.unsafelyUnwrapped
        var index = 0
        while index < 256 {
          outputPointer[index] = subtract(
            outputPointer[index],
            subtrahendPointer[index]
          )
          index += 1
        }
      }
    }
  }

  @inline(__always)
  static func compress(_ value: Coefficient, bitCount: Int) -> Coefficient {
    precondition(bitCount > 0 && bitCount < 12)
    let shifted = UInt32(value) << UInt32(bitCount)
    var quotient = UInt32((UInt64(shifted) * 5_039) >> 24)
    let remainder = shifted &- (quotient &* UInt32(modulus))
    assert(remainder < 2 * UInt32(modulus))

    // The underflow bits implement strict unsigned comparisons without
    // secret-dependent branches. Equal half-way values round down.
    quotient &+= (UInt32(1_664) &- remainder) >> 31
    quotient &+= (UInt32(4_993) &- remainder) >> 31
    return Coefficient(truncatingIfNeeded: quotient & ((1 << bitCount) - 1))
  }

  @inline(__always)
  static func decompress(_ value: Coefficient, bitCount: Int) -> Coefficient {
    precondition(bitCount > 0 && bitCount < 12)
    let product = UInt32(value) &* UInt32(modulus)
    let power = UInt32(1 << bitCount)
    let remainder = product & (power - 1)
    let lower = product >> UInt32(bitCount)
    return Coefficient(
      truncatingIfNeeded: lower &+ (remainder >> UInt32(bitCount - 1))
    )
  }

  static func encode(
    _ polynomial: Span<Coefficient>,
    bitCount: Int,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(polynomial.count == 256)
    precondition(bitCount >= 1 && bitCount <= 12)
    precondition(output.count == 32 * bitCount)

    if bitCount == 12 {
      encode12(polynomial, into: &output)
      return
    }

    var accumulator: UInt64 = 0
    var accumulatorBitCount = 0
    var outputIndex = 0
    var coefficientIndex = 0
    while coefficientIndex < 256 {
      accumulator |= UInt64(polynomial[coefficientIndex]) << UInt64(accumulatorBitCount)
      accumulatorBitCount += bitCount
      while accumulatorBitCount >= 8 {
        output[outputIndex] = UInt8(truncatingIfNeeded: accumulator)
        outputIndex += 1
        accumulator >>= 8
        accumulatorBitCount -= 8
      }
      coefficientIndex += 1
    }
    precondition(outputIndex == output.count && accumulatorBitCount == 0)
  }

  static func decode(
    _ input: Span<UInt8>,
    bitCount: Int,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    precondition(bitCount >= 1 && bitCount <= 12)
    precondition(input.count == 32 * bitCount)
    precondition(polynomial.count == 256)

    if bitCount == 12 {
      decode12(input, into: &polynomial)
      return
    }

    let mask = UInt64((1 << bitCount) - 1)
    var accumulator: UInt64 = 0
    var accumulatorBitCount = 0
    var inputIndex = 0
    var coefficientIndex = 0
    while coefficientIndex < 256 {
      while accumulatorBitCount < bitCount {
        accumulator |= UInt64(input[inputIndex]) << UInt64(accumulatorBitCount)
        accumulatorBitCount += 8
        inputIndex += 1
      }
      let decoded = Coefficient(truncatingIfNeeded: accumulator & mask)
      polynomial[coefficientIndex] = decoded
      accumulator >>= UInt64(bitCount)
      accumulatorBitCount -= bitCount
      coefficientIndex += 1
    }
  }

  static func encodeCompressed(
    _ polynomial: Span<Coefficient>,
    bitCount: Int,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(polynomial.count == 256)
    precondition(bitCount >= 1 && bitCount < 12)
    precondition(output.count == 32 * bitCount)

    switch bitCount {
    case 1:
      encodeCompressed1(polynomial, into: &output)
      return
    case 4:
      encodeCompressed4(polynomial, into: &output)
      return
    case 5:
      encodeCompressed5(polynomial, into: &output)
      return
    case 10:
      encodeCompressed10(polynomial, into: &output)
      return
    case 11:
      encodeCompressed11(polynomial, into: &output)
      return
    default:
      break
    }

    var accumulator: UInt64 = 0
    var accumulatorBitCount = 0
    var outputIndex = 0
    var coefficientIndex = 0
    while coefficientIndex < 256 {
      let value = compress(polynomial[coefficientIndex], bitCount: bitCount)
      accumulator |= UInt64(value) << UInt64(accumulatorBitCount)
      accumulatorBitCount += bitCount
      while accumulatorBitCount >= 8 {
        output[outputIndex] = UInt8(truncatingIfNeeded: accumulator)
        outputIndex += 1
        accumulator >>= 8
        accumulatorBitCount -= 8
      }
      coefficientIndex += 1
    }
    precondition(outputIndex == output.count && accumulatorBitCount == 0)
  }

  private static func encode12(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    // Unsafe boundary invariants:
    // - The caller validated 256 input coefficients and 384 output bytes.
    // - Each iteration reads two initialized UInt16 values and writes three
    //   distinct bytes; neither scoped pointer escapes its closure.
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          let first = input[coefficientIndex]
          let second = input[coefficientIndex + 1]
          destination[outputIndex] = UInt8(truncatingIfNeeded: first)
          destination[outputIndex + 1] = UInt8(
            truncatingIfNeeded: (first >> 8) | (second << 4)
          )
          destination[outputIndex + 2] = UInt8(truncatingIfNeeded: second >> 4)
          coefficientIndex += 2
          outputIndex += 3
        }
      }
    }
  }

  private static func decode12(
    _ input: Span<UInt8>,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    // The scoped pointer, initialization, byte-count, and nonescape
    // invariants match encode12. Public key constructors reject non-canonical
    // external vectors before this internal decoder is reached.
    input.withUnsafeBufferPointer { inputBuffer in
      polynomial.withUnsafeMutableBufferPointer { outputBuffer in
        let source = inputBuffer.baseAddress.unsafelyUnwrapped
        let output = outputBuffer.baseAddress.unsafelyUnwrapped
        var inputIndex = 0
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          let first =
            Coefficient(source[inputIndex])
            | (Coefficient(source[inputIndex + 1] & 0x0F) << 8)
          let second =
            Coefficient(source[inputIndex + 1] >> 4)
            | (Coefficient(source[inputIndex + 2]) << 4)
          output[coefficientIndex] = reduceOnce(first)
          output[coefficientIndex + 1] = reduceOnce(second)
          inputIndex += 3
          coefficientIndex += 2
        }
      }
    }
  }

  private static func encodeCompressed10(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          let first: Coefficient
          let second: Coefficient
          let third: Coefficient
          let fourth: Coefficient
          #if os(macOS) && arch(arm64) && canImport(simd)
            let compressed = compressFour(
              SIMD4(
                input[coefficientIndex],
                input[coefficientIndex + 1],
                input[coefficientIndex + 2],
                input[coefficientIndex + 3]
              ),
              bitCount: 10
            )
            first = compressed[0]
            second = compressed[1]
            third = compressed[2]
            fourth = compressed[3]
          #else
            first = compress(input[coefficientIndex], bitCount: 10)
            second = compress(input[coefficientIndex + 1], bitCount: 10)
            third = compress(input[coefficientIndex + 2], bitCount: 10)
            fourth = compress(input[coefficientIndex + 3], bitCount: 10)
          #endif
          destination[outputIndex] = UInt8(truncatingIfNeeded: first)
          destination[outputIndex + 1] = UInt8(
            truncatingIfNeeded: (first >> 8) | (second << 2)
          )
          destination[outputIndex + 2] = UInt8(
            truncatingIfNeeded: (second >> 6) | (third << 4)
          )
          destination[outputIndex + 3] = UInt8(
            truncatingIfNeeded: (third >> 4) | (fourth << 6)
          )
          destination[outputIndex + 4] = UInt8(truncatingIfNeeded: fourth >> 2)
          coefficientIndex += 4
          outputIndex += 5
        }
      }
    }
  }

  private static func encodeCompressed11(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          let first: Coefficient
          let second: Coefficient
          let third: Coefficient
          let fourth: Coefficient
          let fifth: Coefficient
          let sixth: Coefficient
          let seventh: Coefficient
          let eighth: Coefficient
          #if os(macOS) && arch(arm64) && canImport(simd)
            let firstFour = compressFour(
              SIMD4(
                input[coefficientIndex],
                input[coefficientIndex + 1],
                input[coefficientIndex + 2],
                input[coefficientIndex + 3]
              ),
              bitCount: 11
            )
            let secondFour = compressFour(
              SIMD4(
                input[coefficientIndex + 4],
                input[coefficientIndex + 5],
                input[coefficientIndex + 6],
                input[coefficientIndex + 7]
              ),
              bitCount: 11
            )
            first = firstFour[0]
            second = firstFour[1]
            third = firstFour[2]
            fourth = firstFour[3]
            fifth = secondFour[0]
            sixth = secondFour[1]
            seventh = secondFour[2]
            eighth = secondFour[3]
          #else
            first = compress(input[coefficientIndex], bitCount: 11)
            second = compress(input[coefficientIndex + 1], bitCount: 11)
            third = compress(input[coefficientIndex + 2], bitCount: 11)
            fourth = compress(input[coefficientIndex + 3], bitCount: 11)
            fifth = compress(input[coefficientIndex + 4], bitCount: 11)
            sixth = compress(input[coefficientIndex + 5], bitCount: 11)
            seventh = compress(input[coefficientIndex + 6], bitCount: 11)
            eighth = compress(input[coefficientIndex + 7], bitCount: 11)
          #endif
          destination[outputIndex] = UInt8(truncatingIfNeeded: first)
          destination[outputIndex + 1] = UInt8(
            truncatingIfNeeded: (first >> 8) | (second << 3)
          )
          destination[outputIndex + 2] = UInt8(
            truncatingIfNeeded: (second >> 5) | (third << 6)
          )
          destination[outputIndex + 3] = UInt8(truncatingIfNeeded: third >> 2)
          destination[outputIndex + 4] = UInt8(
            truncatingIfNeeded: (third >> 10) | (fourth << 1)
          )
          destination[outputIndex + 5] = UInt8(
            truncatingIfNeeded: (fourth >> 7) | (fifth << 4)
          )
          destination[outputIndex + 6] = UInt8(
            truncatingIfNeeded: (fifth >> 4) | (sixth << 7)
          )
          destination[outputIndex + 7] = UInt8(truncatingIfNeeded: sixth >> 1)
          destination[outputIndex + 8] = UInt8(
            truncatingIfNeeded: (sixth >> 9) | (seventh << 2)
          )
          destination[outputIndex + 9] = UInt8(
            truncatingIfNeeded: (seventh >> 6) | (eighth << 5)
          )
          destination[outputIndex + 10] = UInt8(truncatingIfNeeded: eighth >> 3)
          coefficientIndex += 8
          outputIndex += 11
        }
      }
    }
  }

  #if os(macOS) && arch(arm64) && canImport(simd)
    @inline(__always)
    private static func compressFour(
      _ values: SIMD4<Coefficient>,
      bitCount: Int
    ) -> SIMD4<Coefficient> {
      let shifted =
        SIMD4<UInt32>(truncatingIfNeeded: values)
        &<< SIMD4(repeating: UInt32(bitCount))
      let reciprocal = SIMD2<UInt32>(repeating: 5_039)
      let lowerProducts = vmull_u32(
        SIMD2(shifted[0], shifted[1]),
        reciprocal
      )
      let upperProducts = vmull_u32(
        SIMD2(shifted[2], shifted[3]),
        reciprocal
      )
      let lowerQuotients = SIMD2<UInt32>(
        truncatingIfNeeded:
          lowerProducts &>> SIMD2<UInt64>(repeating: 24)
      )
      let upperQuotients = SIMD2<UInt32>(
        truncatingIfNeeded:
          upperProducts &>> SIMD2<UInt64>(repeating: 24)
      )
      var quotient = SIMD4(
        lowerQuotients[0],
        lowerQuotients[1],
        upperQuotients[0],
        upperQuotients[1]
      )
      let modulus = SIMD4<UInt32>(repeating: UInt32(Self.modulus))
      let remainder = shifted &- (quotient &* modulus)
      quotient &+=
        (SIMD4<UInt32>(repeating: 1_664) &- remainder)
        &>> SIMD4(repeating: 31)
      quotient &+=
        (SIMD4<UInt32>(repeating: 4_993) &- remainder)
        &>> SIMD4(repeating: 31)
      quotient &= SIMD4(repeating: UInt32((1 << bitCount) - 1))
      return SIMD4<Coefficient>(truncatingIfNeeded: quotient)
    }
  #endif

  private static func encodeCompressed5(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          let first = compress(input[coefficientIndex], bitCount: 5)
          let second = compress(input[coefficientIndex + 1], bitCount: 5)
          let third = compress(input[coefficientIndex + 2], bitCount: 5)
          let fourth = compress(input[coefficientIndex + 3], bitCount: 5)
          let fifth = compress(input[coefficientIndex + 4], bitCount: 5)
          let sixth = compress(input[coefficientIndex + 5], bitCount: 5)
          let seventh = compress(input[coefficientIndex + 6], bitCount: 5)
          let eighth = compress(input[coefficientIndex + 7], bitCount: 5)
          destination[outputIndex] = UInt8(
            truncatingIfNeeded: first | (second << 5)
          )
          destination[outputIndex + 1] = UInt8(
            truncatingIfNeeded: (second >> 3) | (third << 2) | (fourth << 7)
          )
          destination[outputIndex + 2] = UInt8(
            truncatingIfNeeded: (fourth >> 1) | (fifth << 4)
          )
          destination[outputIndex + 3] = UInt8(
            truncatingIfNeeded: (fifth >> 4) | (sixth << 1) | (seventh << 6)
          )
          destination[outputIndex + 4] = UInt8(
            truncatingIfNeeded: (seventh >> 2) | (eighth << 3)
          )
          coefficientIndex += 8
          outputIndex += 5
        }
      }
    }
  }

  private static func encodeCompressed4(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          let first = compress(input[coefficientIndex], bitCount: 4)
          let second = compress(input[coefficientIndex + 1], bitCount: 4)
          destination[outputIndex] = UInt8(
            truncatingIfNeeded: first | (second << 4)
          )
          coefficientIndex += 2
          outputIndex += 1
        }
      }
    }
  }

  private static func encodeCompressed1(
    _ polynomial: Span<Coefficient>,
    into output: inout MutableSpan<UInt8>
  ) {
    polynomial.withUnsafeBufferPointer { inputBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let input = inputBuffer.baseAddress.unsafelyUnwrapped
        let destination = outputBuffer.baseAddress.unsafelyUnwrapped
        var coefficientIndex = 0
        var outputIndex = 0
        while coefficientIndex < 256 {
          var byte: UInt16 = 0
          var bit = 0
          while bit < 8 {
            byte |= compress(input[coefficientIndex + bit], bitCount: 1) << bit
            bit += 1
          }
          destination[outputIndex] = UInt8(truncatingIfNeeded: byte)
          coefficientIndex += 8
          outputIndex += 1
        }
      }
    }
  }

  static func decodeDecompressed(
    _ input: Span<UInt8>,
    bitCount: Int,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    switch bitCount {
    case 4:
      decodeDecompressed4(input, into: &polynomial)
      return
    case 5:
      decodeDecompressed5(input, into: &polynomial)
      return
    case 10:
      decodeDecompressed10(input, into: &polynomial)
      return
    case 11:
      decodeDecompressed11(input, into: &polynomial)
      return
    default:
      break
    }

    decode(input, bitCount: bitCount, into: &polynomial)
    var index = 0
    while index < polynomial.count {
      polynomial[index] = decompress(polynomial[index], bitCount: bitCount)
      index += 1
    }
  }

  private static func decodeDecompressed10(
    _ input: Span<UInt8>,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    precondition(input.count == 320 && polynomial.count == 256)
    input.withUnsafeBufferPointer { inputBuffer in
      polynomial.withUnsafeMutableBufferPointer { outputBuffer in
        let source = inputBuffer.baseAddress.unsafelyUnwrapped
        let output = outputBuffer.baseAddress.unsafelyUnwrapped
        var inputIndex = 0
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          let first =
            Coefficient(source[inputIndex])
            | (Coefficient(source[inputIndex + 1] & 0x03) << 8)
          let second =
            Coefficient(source[inputIndex + 1] >> 2)
            | (Coefficient(source[inputIndex + 2] & 0x0F) << 6)
          let third =
            Coefficient(source[inputIndex + 2] >> 4)
            | (Coefficient(source[inputIndex + 3] & 0x3F) << 4)
          let fourth =
            Coefficient(source[inputIndex + 3] >> 6)
            | (Coefficient(source[inputIndex + 4]) << 2)
          output[coefficientIndex] = decompress(first, bitCount: 10)
          output[coefficientIndex + 1] = decompress(second, bitCount: 10)
          output[coefficientIndex + 2] = decompress(third, bitCount: 10)
          output[coefficientIndex + 3] = decompress(fourth, bitCount: 10)
          inputIndex += 5
          coefficientIndex += 4
        }
      }
    }
  }

  private static func decodeDecompressed11(
    _ input: Span<UInt8>,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    precondition(input.count == 352 && polynomial.count == 256)
    input.withUnsafeBufferPointer { inputBuffer in
      polynomial.withUnsafeMutableBufferPointer { outputBuffer in
        let source = inputBuffer.baseAddress.unsafelyUnwrapped
        let output = outputBuffer.baseAddress.unsafelyUnwrapped
        var inputIndex = 0
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          let first =
            Coefficient(source[inputIndex])
            | (Coefficient(source[inputIndex + 1] & 0x07) << 8)
          let second =
            Coefficient(source[inputIndex + 1] >> 3)
            | (Coefficient(source[inputIndex + 2] & 0x3F) << 5)
          let third =
            Coefficient(source[inputIndex + 2] >> 6)
            | (Coefficient(source[inputIndex + 3]) << 2)
            | (Coefficient(source[inputIndex + 4] & 0x01) << 10)
          let fourth =
            Coefficient(source[inputIndex + 4] >> 1)
            | (Coefficient(source[inputIndex + 5] & 0x0F) << 7)
          let fifth =
            Coefficient(source[inputIndex + 5] >> 4)
            | (Coefficient(source[inputIndex + 6] & 0x7F) << 4)
          let sixth =
            Coefficient(source[inputIndex + 6] >> 7)
            | (Coefficient(source[inputIndex + 7]) << 1)
            | (Coefficient(source[inputIndex + 8] & 0x03) << 9)
          let seventh =
            Coefficient(source[inputIndex + 8] >> 2)
            | (Coefficient(source[inputIndex + 9] & 0x1F) << 6)
          let eighth =
            Coefficient(source[inputIndex + 9] >> 5)
            | (Coefficient(source[inputIndex + 10]) << 3)
          output[coefficientIndex] = decompress(first, bitCount: 11)
          output[coefficientIndex + 1] = decompress(second, bitCount: 11)
          output[coefficientIndex + 2] = decompress(third, bitCount: 11)
          output[coefficientIndex + 3] = decompress(fourth, bitCount: 11)
          output[coefficientIndex + 4] = decompress(fifth, bitCount: 11)
          output[coefficientIndex + 5] = decompress(sixth, bitCount: 11)
          output[coefficientIndex + 6] = decompress(seventh, bitCount: 11)
          output[coefficientIndex + 7] = decompress(eighth, bitCount: 11)
          inputIndex += 11
          coefficientIndex += 8
        }
      }
    }
  }

  private static func decodeDecompressed5(
    _ input: Span<UInt8>,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    precondition(input.count == 160 && polynomial.count == 256)
    input.withUnsafeBufferPointer { inputBuffer in
      polynomial.withUnsafeMutableBufferPointer { outputBuffer in
        let source = inputBuffer.baseAddress.unsafelyUnwrapped
        let output = outputBuffer.baseAddress.unsafelyUnwrapped
        var inputIndex = 0
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          let first = Coefficient(source[inputIndex] & 0x1F)
          let second =
            Coefficient(source[inputIndex] >> 5)
            | (Coefficient(source[inputIndex + 1] & 0x03) << 3)
          let third = Coefficient((source[inputIndex + 1] >> 2) & 0x1F)
          let fourth =
            Coefficient(source[inputIndex + 1] >> 7)
            | (Coefficient(source[inputIndex + 2] & 0x0F) << 1)
          let fifth =
            Coefficient(source[inputIndex + 2] >> 4)
            | (Coefficient(source[inputIndex + 3] & 0x01) << 4)
          let sixth = Coefficient((source[inputIndex + 3] >> 1) & 0x1F)
          let seventh =
            Coefficient(source[inputIndex + 3] >> 6)
            | (Coefficient(source[inputIndex + 4] & 0x07) << 2)
          let eighth = Coefficient(source[inputIndex + 4] >> 3)
          output[coefficientIndex] = decompress(first, bitCount: 5)
          output[coefficientIndex + 1] = decompress(second, bitCount: 5)
          output[coefficientIndex + 2] = decompress(third, bitCount: 5)
          output[coefficientIndex + 3] = decompress(fourth, bitCount: 5)
          output[coefficientIndex + 4] = decompress(fifth, bitCount: 5)
          output[coefficientIndex + 5] = decompress(sixth, bitCount: 5)
          output[coefficientIndex + 6] = decompress(seventh, bitCount: 5)
          output[coefficientIndex + 7] = decompress(eighth, bitCount: 5)
          inputIndex += 5
          coefficientIndex += 8
        }
      }
    }
  }

  private static func decodeDecompressed4(
    _ input: Span<UInt8>,
    into polynomial: inout MutableSpan<Coefficient>
  ) {
    precondition(input.count == 128 && polynomial.count == 256)
    input.withUnsafeBufferPointer { inputBuffer in
      polynomial.withUnsafeMutableBufferPointer { outputBuffer in
        let source = inputBuffer.baseAddress.unsafelyUnwrapped
        let output = outputBuffer.baseAddress.unsafelyUnwrapped
        var inputIndex = 0
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          output[coefficientIndex] = decompress(
            Coefficient(source[inputIndex] & 0x0F),
            bitCount: 4
          )
          output[coefficientIndex + 1] = decompress(
            Coefficient(source[inputIndex] >> 4),
            bitCount: 4
          )
          inputIndex += 1
          coefficientIndex += 2
        }
      }
    }
  }

  static func sampleNTT(
    seed: Span<UInt8>,
    row: UInt8,
    column: UInt8,
    into polynomial: inout MutableSpan<Coefficient>
  ) throws(CryptoInputError) {
    precondition(seed.count == 32 && polynomial.count == 256)
    var context = KeccakCore(rateByteCount: 168, domainSeparator: 0x1F)
    try context.update(seed)
    try context.update(byte: column)
    try context.update(byte: row)

    var sample = ContiguousArray<UInt8>(repeating: 0, count: 168)
    var coefficientIndex = 0
    while coefficientIndex < 256 {
      var destination = sample.mutableSpan
      context.squeeze(into: &destination)
      var sampleIndex = 0
      while sampleIndex < sample.count && coefficientIndex < 256 {
        let first =
          Int32(sample[sampleIndex])
          + 256 * Int32(sample[sampleIndex + 1] & 0x0F)
        let second =
          Int32(sample[sampleIndex + 1] >> 4)
          + 16 * Int32(sample[sampleIndex + 2])
        if first < modulus {
          polynomial[coefficientIndex] = Coefficient(truncatingIfNeeded: first)
          coefficientIndex += 1
        }
        if second < modulus && coefficientIndex < 256 {
          polynomial[coefficientIndex] = Coefficient(truncatingIfNeeded: second)
          coefficientIndex += 1
        }
        sampleIndex += 3
      }
    }
  }

  static func sampleCBD(
    seed: Span<UInt8>,
    nonce: UInt8,
    eta: Int,
    into polynomial: inout MutableSpan<Coefficient>
  ) throws(KEMError) {
    precondition(seed.count == 32 && (eta == 2 || eta == 3) && polynomial.count == 256)
    let outputByteCount = 64 * eta
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(outputByteCount)
    } catch {
      throw .secretMemory(error)
    }

    let expanded: SecretBytes
    do {
      expanded = try pseudorandomBytes(
        seed: seed,
        nonce: nonce,
        byteCount: byteCount
      )
    } catch {
      throw .primitiveFailure(error)
    }

    expanded.withBorrowedBytes { bytes in
      if eta == 2 {
        var byteIndex = 0
        while byteIndex < 128 {
          let coefficientIndex = byteIndex * 2
          let byte = bytes[byteIndex]
          polynomial[coefficientIndex] = centeredBinomialEta2(byte & 0x0F)
          polynomial[coefficientIndex + 1] = centeredBinomialEta2(byte >> 4)
          byteIndex += 1
        }
      } else {
        var coefficientIndex = 0
        while coefficientIndex < 256 {
          let baseBit = 6 * coefficientIndex
          var x: Int32 = 0
          var y: Int32 = 0
          var bit = 0
          while bit < 3 {
            x += extractedBit(bytes, at: baseBit + bit)
            y += extractedBit(bytes, at: baseBit + 3 + bit)
            bit += 1
          }
          polynomial[coefficientIndex] = reduceOnce(
            Coefficient(truncatingIfNeeded: x - y + Int32(modulus))
          )
          coefficientIndex += 1
        }
      }
    }
  }

  @inline(__always)
  private static func centeredBinomialEta2(_ value: UInt8) -> Coefficient {
    let difference =
      Int32(value & 1) + Int32((value >> 1) & 1)
      - Int32((value >> 2) & 1) - Int32((value >> 3) & 1)
    return Coefficient(
      truncatingIfNeeded:
        difference + ((difference >> 31) & Int32(modulus))
    )
  }

  @inline(__always)
  private static func extractedBit(_ bytes: Span<UInt8>, at bitIndex: Int) -> Int32 {
    Int32((bytes[bitIndex / 8] >> UInt8(bitIndex & 7)) & 1)
  }

  private static func pseudorandomBytes(
    seed: Span<UInt8>,
    nonce: UInt8,
    byteCount: SecretByteCount
  ) throws(CryptoInputError) -> SecretBytes {
    try SecretBytes(byteCount: byteCount) {
      (output: inout MutableSpan<UInt8>) throws(CryptoInputError) in
      var context = SHAKE256Context()
      defer { context.erase() }
      try context.update(seed)
      try context.update(byte: nonce)
      context.squeeze(into: &output)
    }
  }
}
