import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class MLKEMArithmeticTests: XCTestCase {
  func testNTTMultiplicationMatchesNegacyclicReference() {
    var lhs = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var rhs = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var product = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var expected = ContiguousArray<MLKEMArithmetic.Coefficient>(repeating: 0, count: 256)

    lhs.withMutablePolynomial(at: 0) { polynomial in
      var index = 0
      while index < 256 {
        polynomial[index] = MLKEMArithmetic.Coefficient((index * 17 + 9) % 3_329)
        index += 1
      }
    }
    rhs.withMutablePolynomial(at: 0) { polynomial in
      var index = 0
      while index < 256 {
        polynomial[index] = MLKEMArithmetic.Coefficient((index * index + 31) % 3_329)
        index += 1
      }
    }

    lhs.withPolynomial(at: 0) { left in
      rhs.withPolynomial(at: 0) { right in
        var leftIndex = 0
        while leftIndex < 256 {
          var rightIndex = 0
          while rightIndex < 256 {
            let degree = leftIndex + rightIndex
            let target = degree & 255
            let sign: Int64 = degree >= 256 ? -1 : 1
            expected[target] = MLKEMArithmetic.reduce(
              Int64(expected[target])
                + sign * Int64(left[leftIndex]) * Int64(right[rightIndex])
            )
            rightIndex += 1
          }
          leftIndex += 1
        }
      }
    }

    lhs.withMutablePolynomial(at: 0) { MLKEMArithmetic.forwardNTT(&$0) }
    rhs.withMutablePolynomial(at: 0) { MLKEMArithmetic.forwardNTT(&$0) }
    product.withMutablePolynomial(at: 0) { output in
      lhs.withPolynomial(at: 0) { left in
        rhs.withPolynomial(at: 0) { right in
          MLKEMArithmetic.multiplyNTTs(
            left,
            right,
            accumulatingInto: &output,
            initialize: true
          )
        }
      }
      MLKEMArithmetic.inverseNTT(&output)
    }

    product.withPolynomial(at: 0) { actual in
      var index = 0
      while index < 256 {
        XCTAssertEqual(actual[index], expected[index], "coefficient \(index)")
        index += 1
      }
    }
  }

  func testNTTAccumulationMatchesSeparateProducts() {
    var left = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)
    var right = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)
    var accumulated = MLKEMPolynomialStorage(
      polynomialCount: 1,
      sensitivity: .secret
    )
    var expected = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var secondProduct = MLKEMPolynomialStorage(
      polynomialCount: 1,
      sensitivity: .secret
    )

    var polynomialIndex = 0
    while polynomialIndex < 2 {
      left.withMutablePolynomial(at: polynomialIndex) { polynomial in
        var coefficientIndex = 0
        while coefficientIndex < MLKEMPolynomialStorage.coefficientCount {
          polynomial[coefficientIndex] = MLKEMArithmetic.Coefficient(
            (coefficientIndex * (31 + polynomialIndex * 12) + 7) % 3_329
          )
          coefficientIndex += 1
        }
        MLKEMArithmetic.forwardNTT(&polynomial)
      }
      right.withMutablePolynomial(at: polynomialIndex) { polynomial in
        var coefficientIndex = 0
        while coefficientIndex < MLKEMPolynomialStorage.coefficientCount {
          polynomial[coefficientIndex] = MLKEMArithmetic.Coefficient(
            (coefficientIndex * (47 + polynomialIndex * 10) + 19) % 3_329
          )
          coefficientIndex += 1
        }
        MLKEMArithmetic.forwardNTT(&polynomial)
      }
      polynomialIndex += 1
    }

    accumulated.withMutablePolynomial(at: 0) { output in
      left.withPolynomial(at: 0) { lhs in
        right.withPolynomial(at: 0) { rhs in
          MLKEMArithmetic.multiplyNTTs(
            lhs,
            rhs,
            accumulatingInto: &output,
            initialize: true
          )
        }
      }
      left.withPolynomial(at: 1) { lhs in
        right.withPolynomial(at: 1) { rhs in
          MLKEMArithmetic.multiplyNTTs(
            lhs,
            rhs,
            accumulatingInto: &output,
            initialize: false
          )
        }
      }
    }

    expected.withMutablePolynomial(at: 0) { output in
      left.withPolynomial(at: 0) { lhs in
        right.withPolynomial(at: 0) { rhs in
          MLKEMArithmetic.multiplyNTTs(
            lhs,
            rhs,
            accumulatingInto: &output,
            initialize: true
          )
        }
      }
    }
    secondProduct.withMutablePolynomial(at: 0) { output in
      left.withPolynomial(at: 1) { lhs in
        right.withPolynomial(at: 1) { rhs in
          MLKEMArithmetic.multiplyNTTs(
            lhs,
            rhs,
            accumulatingInto: &output,
            initialize: true
          )
        }
      }
    }
    expected.withMutablePolynomial(at: 0) { output in
      secondProduct.withPolynomial(at: 0) { addend in
        MLKEMArithmetic.add(addend, into: &output)
      }
    }

    accumulated.withPolynomial(at: 0) { actual in
      expected.withPolynomial(at: 0) { reference in
        var index = 0
        while index < MLKEMPolynomialStorage.coefficientCount {
          XCTAssertEqual(actual[index], reference[index], "coefficient \(index)")
          index += 1
        }
      }
    }
  }

  func testInverseNTTWithFusedAdditionMatchesSeparateOperations() {
    var separate = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var fused = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    var addend = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)

    separate.withMutablePolynomial(at: 0) { polynomial in
      fused.withMutablePolynomial(at: 0) { fusedPolynomial in
        addend.withMutablePolynomial(at: 0) { addendPolynomial in
          var index = 0
          while index < MLKEMPolynomialStorage.coefficientCount {
            let value = MLKEMArithmetic.Coefficient((index * 37 + 19) % 3_329)
            polynomial[index] = value
            fusedPolynomial[index] = value
            addendPolynomial[index] = MLKEMArithmetic.Coefficient(
              (index * 53 + 11) % 3_329
            )
            index += 1
          }
        }
      }
    }

    separate.withMutablePolynomial(at: 0) { polynomial in
      MLKEMArithmetic.inverseNTT(&polynomial)
      addend.withPolynomial(at: 0) { addendPolynomial in
        MLKEMArithmetic.add(addendPolynomial, into: &polynomial)
      }
    }
    fused.withMutablePolynomial(at: 0) { polynomial in
      addend.withPolynomial(at: 0) { addendPolynomial in
        MLKEMArithmetic.inverseNTT(&polynomial, adding: addendPolynomial)
      }
    }

    separate.withPolynomial(at: 0) { expected in
      fused.withPolynomial(at: 0) { actual in
        var index = 0
        while index < MLKEMPolynomialStorage.coefficientCount {
          XCTAssertEqual(actual[index], expected[index], "coefficient \(index)")
          index += 1
        }
      }
    }
  }

  func testByteEncodingRoundTripsEverySupportedWidth() {
    for bitCount in 1...12 {
      var original = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
      var decoded = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
      let valueLimit = bitCount == 12 ? 3_329 : 1 << bitCount
      original.withMutablePolynomial(at: 0) { polynomial in
        var index = 0
        while index < 256 {
          polynomial[index] = MLKEMArithmetic.Coefficient(
            (index * 29 + 7) % valueLimit
          )
          index += 1
        }
      }

      var encoded = ContiguousArray<UInt8>(repeating: 0, count: 32 * bitCount)
      original.withPolynomial(at: 0) { polynomial in
        var output = encoded.mutableSpan
        MLKEMArithmetic.encode(polynomial, bitCount: bitCount, into: &output)
      }
      decoded.withMutablePolynomial(at: 0) { polynomial in
        MLKEMArithmetic.decode(encoded.span, bitCount: bitCount, into: &polynomial)
      }

      original.withPolynomial(at: 0) { expected in
        decoded.withPolynomial(at: 0) { actual in
          var index = 0
          while index < 256 {
            XCTAssertEqual(actual[index], expected[index])
            index += 1
          }
        }
      }
    }
  }

  func testCompressionRoundTripForEncodedDomain() {
    for bitCount in 1...11 {
      let limit = 1 << bitCount
      var encoded = 0
      while encoded < limit {
        let decompressed = MLKEMArithmetic.decompress(
          MLKEMArithmetic.Coefficient(encoded),
          bitCount: bitCount
        )
        XCTAssertEqual(
          MLKEMArithmetic.compress(decompressed, bitCount: bitCount),
          MLKEMArithmetic.Coefficient(encoded)
        )
        encoded += 1
      }
    }
  }

  func testCompressionMatchesDivisionReferenceForEveryCanonicalValue() {
    for bitCount in 1...11 {
      let scale = Int64(1 << bitCount)
      for value in 0..<Int(MLKEMArithmetic.modulus) {
        let expected = MLKEMArithmetic.Coefficient(
          ((Int64(value) * scale + Int64(MLKEMArithmetic.modulus / 2))
            / Int64(MLKEMArithmetic.modulus)) % scale
        )
        XCTAssertEqual(
          MLKEMArithmetic.compress(
            MLKEMArithmetic.Coefficient(value),
            bitCount: bitCount
          ),
          expected,
          "bitCount \(bitCount), value \(value)"
        )
      }
    }
  }

  func testSpecializedCompressedEncodingMatchesScalarReference() {
    let bitCounts = [1, 4, 5, 10, 11]
    var original = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    original.withMutablePolynomial(at: 0) { polynomial in
      var index = 0
      while index < MLKEMPolynomialStorage.coefficientCount {
        polynomial[index] = MLKEMArithmetic.Coefficient(
          (index * index * 17 + index * 53 + 23) % 3_329
        )
        index += 1
      }
    }

    for bitCount in bitCounts {
      var compressed = MLKEMPolynomialStorage(
        polynomialCount: 1,
        sensitivity: .secret
      )
      original.withPolynomial(at: 0) { input in
        compressed.withMutablePolynomial(at: 0) { output in
          var index = 0
          while index < MLKEMPolynomialStorage.coefficientCount {
            output[index] = MLKEMArithmetic.compress(
              input[index],
              bitCount: bitCount
            )
            index += 1
          }
        }
      }

      var expected = ContiguousArray<UInt8>(
        repeating: 0,
        count: 32 * bitCount
      )
      compressed.withPolynomial(at: 0) { polynomial in
        var destination = expected.mutableSpan
        MLKEMArithmetic.encode(
          polynomial,
          bitCount: bitCount,
          into: &destination
        )
      }

      var actual = ContiguousArray<UInt8>(repeating: 0, count: 32 * bitCount)
      original.withPolynomial(at: 0) { polynomial in
        var destination = actual.mutableSpan
        MLKEMArithmetic.encodeCompressed(
          polynomial,
          bitCount: bitCount,
          into: &destination
        )
      }
      XCTAssertEqual(actual, expected, "bitCount \(bitCount)")
    }
  }

  func testSampleNTTMatchesIndependentSHAKE128Fixture() throws {
    let seed = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let expected: [MLKEMArithmetic.Coefficient] = [
      2944, 3017, 340, 1184, 3243, 1708, 2458, 2285,
      2772, 2391, 413, 258, 1833, 1537, 2203, 2680,
      3170, 1749, 2729, 266, 1070, 739, 1237, 1049,
    ]
    var storage = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)
    try storage.withMutablePolynomial(at: 0) { polynomial in
      try MLKEMArithmetic.sampleNTT(
        seed: seed.span,
        row: 0,
        column: 0,
        into: &polynomial
      )
    }
    storage.withPolynomial(at: 0) { polynomial in
      var index = 0
      while index < expected.count {
        XCTAssertEqual(polynomial[index], expected[index])
        index += 1
      }
    }
  }

  func testTwoWaySampleNTTMatchesScalarImplementation() throws {
    let seed = ContiguousArray<UInt8>((0..<32).map(UInt8.init))
    let suffixes: [(UInt8, UInt8)] = [(0, 0), (3, 3)]
    var expected = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)
    var actual = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)

    var index = 0
    while index < suffixes.count {
      let suffix = suffixes[index]
      try expected.withMutablePolynomial(at: index) { polynomial in
        try MLKEMArithmetic.sampleNTT(
          seed: seed.span,
          row: suffix.1,
          column: suffix.0,
          into: &polynomial
        )
      }
      index += 1
    }

    var sampler = KeccakX2Core(
      seed: seed.span,
      firstSuffix: suffixes[0],
      secondSuffix: suffixes[1]
    )
    actual.withTwoMutablePolynomials(startingAt: 0) {
      first,
      second in
      sampler.sampleNTT(
        first: &first,
        second: &second
      )
    }

    index = 0
    while index < suffixes.count {
      expected.withPolynomial(at: index) { expectedPolynomial in
        actual.withPolynomial(at: index) { actualPolynomial in
          var coefficient = 0
          while coefficient < MLKEMPolynomialStorage.coefficientCount {
            XCTAssertEqual(
              actualPolynomial[coefficient],
              expectedPolynomial[coefficient],
              "polynomial \(index), coefficient \(coefficient)"
            )
            coefficient += 1
          }
        }
      }
      index += 1
    }
  }

  func testTwoWayCBDEta2MatchesScalarImplementation() throws {
    let seed = ContiguousArray<UInt8>((0..<32).map { UInt8($0 * 7) })
    var expected = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)
    var actual = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)

    var index = 0
    while index < 2 {
      try expected.withMutablePolynomial(at: index) { polynomial in
        try MLKEMArithmetic.sampleCBD(
          seed: seed.span,
          nonce: UInt8(11 + index),
          eta: 2,
          into: &polynomial
        )
      }
      index += 1
    }

    var sampler = KeccakX2Core(
      secretSeed: seed.span,
      firstNonce: 11,
      secondNonce: 12
    )
    actual.withTwoMutablePolynomials(startingAt: 0) {
      first,
      second in
      sampler.sampleCBDEta2(
        first: &first,
        second: &second
      )
    }

    index = 0
    while index < 2 {
      expected.withPolynomial(at: index) { expectedPolynomial in
        actual.withPolynomial(at: index) { actualPolynomial in
          var coefficient = 0
          while coefficient < MLKEMPolynomialStorage.coefficientCount {
            XCTAssertEqual(
              actualPolynomial[coefficient],
              expectedPolynomial[coefficient],
              "polynomial \(index), coefficient \(coefficient)"
            )
            coefficient += 1
          }
        }
      }
      index += 1
    }
  }

  func testTwoWaySHA3_512MatchesScalarImplementation() throws {
    let first = ContiguousArray<UInt8>((0..<32).map { UInt8($0 * 7 + 5) })
    let second = ContiguousArray<UInt8>(
      (0..<32).map { UInt8(truncatingIfNeeded: $0 * 13 + 9) }
    )
    var scalarOutput = ContiguousArray<UInt8>(repeating: 0, count: 64)
    var parallelOutput = ContiguousArray<UInt8>(repeating: 0, count: 64)

    var scalar = SHA3_512Context()
    try scalar.update(first.span)
    try scalar.update(second.span)
    var scalarDestination = scalarOutput.mutableSpan
    try scalar.finalize(into: &scalarDestination)

    var parallel = KeccakX2Core(sensitivity: .secret)
    var parallelDestination = parallelOutput.mutableSpan
    parallel.sha3_512(
      first: first.span,
      second: second.span,
      into: &parallelDestination
    )
    XCTAssertEqual(parallelOutput, scalarOutput)

    scalar = SHA3_512Context()
    try scalar.update(first.span)
    try scalar.update(byte: 4)
    scalarOutput = ContiguousArray(repeating: 0, count: 64)
    scalarDestination = scalarOutput.mutableSpan
    try scalar.finalize(into: &scalarDestination)

    parallelOutput = ContiguousArray(repeating: 0, count: 64)
    parallelDestination = parallelOutput.mutableSpan
    parallel.sha3_512(first: first.span, suffix: 4, into: &parallelDestination)
    XCTAssertEqual(parallelOutput, scalarOutput)
  }

  func testTwoWaySHA3_256MatchesScalarImplementationAcrossRateBoundaries() throws {
    let lengths = [0, 1, 7, 8, 135, 136, 137, 1_184, 1_568]
    for length in lengths {
      let input = ContiguousArray<UInt8>(
        (0..<length).map { UInt8(truncatingIfNeeded: $0 * 29 + 17) }
      )
      var scalarOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)
      var parallelOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)

      var scalar = SHA3_256Context()
      try scalar.update(input.span)
      var scalarDestination = scalarOutput.mutableSpan
      try scalar.finalize(into: &scalarDestination)

      var parallel = KeccakX2Core(sensitivity: .publicData)
      var parallelDestination = parallelOutput.mutableSpan
      parallel.sha3_256(input.span, into: &parallelDestination)

      XCTAssertEqual(parallelOutput, scalarOutput, "input length \(length)")
    }
  }

  func testTwoWaySHAKE256MatchesScalarImplementationAcrossRateBoundaries() throws {
    let first = ContiguousArray<UInt8>(
      (0..<32).map { UInt8(truncatingIfNeeded: $0 * 11 + 3) }
    )
    let secondLengths = [0, 1, 103, 104, 105, 1_088, 1_568]
    for secondLength in secondLengths {
      let second = ContiguousArray<UInt8>(
        (0..<secondLength).map { UInt8(truncatingIfNeeded: $0 * 29 + 17) }
      )
      var scalarOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)
      var parallelOutput = ContiguousArray<UInt8>(repeating: 0, count: 32)

      var scalar = SHAKE256Context()
      try scalar.update(first.span)
      try scalar.update(second.span)
      var scalarDestination = scalarOutput.mutableSpan
      scalar.squeeze(into: &scalarDestination)

      var parallel = KeccakX2Core(sensitivity: .secret)
      var parallelDestination = parallelOutput.mutableSpan
      parallel.shake256(
        first: first.span,
        second: second.span,
        into: &parallelDestination
      )

      XCTAssertEqual(
        parallelOutput,
        scalarOutput,
        "second input length \(secondLength)"
      )
    }
  }

  func testSingleOutputTwoWayTailMatchesScalarImplementations() throws {
    let seed = ContiguousArray<UInt8>(
      (0..<32).map { UInt8(truncatingIfNeeded: $0 * 13) }
    )
    var expected = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)
    var actual = MLKEMPolynomialStorage(polynomialCount: 2, sensitivity: .secret)

    try expected.withMutablePolynomial(at: 0) { polynomial in
      try MLKEMArithmetic.sampleNTT(
        seed: seed.span,
        row: 2,
        column: 1,
        into: &polynomial
      )
    }
    var nttSampler = KeccakX2Core(
      seed: seed.span,
      firstSuffix: (1, 2),
      secondSuffix: (1, 2)
    )
    actual.withMutablePolynomial(at: 0) { polynomial in
      nttSampler.sampleNTT(into: &polynomial)
    }

    try expected.withMutablePolynomial(at: 1) { polynomial in
      try MLKEMArithmetic.sampleCBD(
        seed: seed.span,
        nonce: 19,
        eta: 2,
        into: &polynomial
      )
    }
    var cbdSampler = KeccakX2Core(
      secretSeed: seed.span,
      firstNonce: 19,
      secondNonce: 19
    )
    actual.withMutablePolynomial(at: 1) { polynomial in
      cbdSampler.sampleCBDEta2(into: &polynomial)
    }

    var polynomialIndex = 0
    while polynomialIndex < 2 {
      expected.withPolynomial(at: polynomialIndex) { expectedPolynomial in
        actual.withPolynomial(at: polynomialIndex) { actualPolynomial in
          var coefficient = 0
          while coefficient < MLKEMPolynomialStorage.coefficientCount {
            XCTAssertEqual(
              actualPolynomial[coefficient],
              expectedPolynomial[coefficient],
              "polynomial \(polynomialIndex), coefficient \(coefficient)"
            )
            coefficient += 1
          }
        }
      }
      polynomialIndex += 1
    }
  }
}
