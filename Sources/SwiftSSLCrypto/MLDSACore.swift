import SwiftSSLCore

#if os(macOS) && arch(arm64) && canImport(simd)
  import simd
#endif

private enum MLDSAArithmeticConstants {
  static let degree = 256
  static let prime: UInt32 = 8_380_417
  static let primeNegInverse: UInt32 = 4_236_238_847
  static let halfPrime: UInt32 = 4_190_208
  static let inverseDegreeDoubleMontgomery: UInt32 = 41_978
  static let droppedBits = 13

  static let roots: [UInt32] = [
    4_193_792, 25_847, 5_771_523, 7_861_508, 237_124, 7_602_457,
    7_504_169, 466_468, 1_826_347, 2_353_451, 8_021_166, 6_288_512,
    3_119_733, 5_495_562, 3_111_497, 2_680_103, 2_725_464, 1_024_112,
    7_300_517, 3_585_928, 7_830_929, 7_260_833, 2_619_752, 6_271_868,
    6_262_231, 4_520_680, 6_980_856, 5_102_745, 1_757_237, 8_360_995,
    4_010_497, 280_005, 2_706_023, 95_776, 3_077_325, 3_530_437,
    6_718_724, 4_788_269, 5_842_901, 3_915_439, 4_519_302, 5_336_701,
    3_574_422, 5_512_770, 3_539_968, 8_079_950, 2_348_700, 7_841_118,
    6_681_150, 6_736_599, 3_505_694, 4_558_682, 3_507_263, 6_239_768,
    6_779_997, 3_699_596, 811_944, 531_354, 954_230, 3_881_043,
    3_900_724, 5_823_537, 2_071_892, 5_582_638, 4_450_022, 6_851_714,
    4_702_672, 5_339_162, 6_927_966, 3_475_950, 2_176_455, 6_795_196,
    7_122_806, 1_939_314, 4_296_819, 7_380_215, 5_190_273, 5_223_087,
    4_747_489, 126_922, 3_412_210, 7_396_998, 2_147_896, 2_715_295,
    5_412_772, 4_686_924, 7_969_390, 5_903_370, 7_709_315, 7_151_892,
    8_357_436, 7_072_248, 7_998_430, 1_349_076, 1_852_771, 6_949_987,
    5_037_034, 264_944, 508_951, 3_097_992, 44_288, 7_280_319,
    904_516, 3_958_618, 4_656_075, 8_371_839, 1_653_064, 5_130_689,
    2_389_356, 8_169_440, 759_969, 7_063_561, 189_548, 4_827_145,
    3_159_746, 6_529_015, 5_971_092, 8_202_977, 1_315_589, 1_341_330,
    1_285_669, 6_795_489, 7_567_685, 6_940_675, 5_361_315, 4_499_357,
    4_751_448, 3_839_961, 2_091_667, 3_407_706, 2_316_500, 3_817_976,
    5_037_939, 2_244_091, 5_933_984, 4_817_955, 266_997, 2_434_439,
    7_144_689, 3_513_181, 4_860_065, 4_621_053, 7_183_191, 5_187_039,
    900_702, 1_859_098, 909_542, 819_034, 495_491, 6_767_243,
    8_337_157, 7_857_917, 7_725_090, 5_257_975, 2_031_748, 3_207_046,
    4_823_422, 7_855_319, 7_611_795, 4_784_579, 342_297, 286_988,
    5_942_594, 4_108_315, 3_437_287, 5_038_140, 1_735_879, 203_044,
    2_842_341, 2_691_481, 5_790_267, 1_265_009, 4_055_324, 1_247_620,
    2_486_353, 1_595_974, 4_613_401, 1_250_494, 2_635_921, 4_832_145,
    5_386_378, 1_869_119, 1_903_435, 7_329_447, 7_047_359, 1_237_275,
    5_062_207, 6_950_192, 7_929_317, 1_312_455, 3_306_115, 6_417_775,
    7_100_756, 1_917_081, 5_834_105, 7_005_614, 1_500_165, 777_191,
    2_235_880, 3_406_031, 7_838_005, 5_548_557, 6_709_241, 6_533_464,
    5_796_124, 4_656_147, 594_136, 4_603_424, 6_366_809, 2_432_395,
    2_454_455, 8_215_696, 1_957_272, 3_369_112, 185_531, 7_173_032,
    5_196_991, 162_844, 1_616_392, 3_014_001, 810_149, 1_652_634,
    4_686_184, 6_581_310, 5_341_501, 3_523_897, 3_866_901, 269_760,
    2_213_111, 7_404_533, 1_717_735, 472_078, 7_953_734, 1_723_600,
    6_577_327, 1_910_376, 6_712_985, 7_276_084, 8_119_771, 4_546_524,
    5_441_381, 6_144_432, 7_959_518, 6_094_090, 183_443, 7_403_526,
    1_612_842, 4_834_730, 7_826_001, 3_919_660, 8_332_111, 7_018_208,
    3_937_738, 1_400_424, 7_534_263, 1_976_782,
  ]
}

struct MLDSACore {
  private typealias Coefficients = ContiguousArray<UInt32>

  let parameterSet: MLDSAParameterSet

  init(parameterSet: MLDSAParameterSet) {
    self.parameterSet = parameterSet
  }
  private var degree: Int { MLDSAArithmeticConstants.degree }
  private var k: Int { parameterSet.k }
  private var l: Int { parameterSet.l }
  private var prime: UInt32 { MLDSAArithmeticConstants.prime }
  private var primeNegInverse: UInt32 { MLDSAArithmeticConstants.primeNegInverse }
  private var halfPrime: UInt32 { MLDSAArithmeticConstants.halfPrime }
  private var inverseDegreeDoubleMontgomery: UInt32 {
    MLDSAArithmeticConstants.inverseDegreeDoubleMontgomery
  }
  private var droppedBits: Int { MLDSAArithmeticConstants.droppedBits }
  private var eta: UInt32 { parameterSet.eta }
  private var gamma1: UInt32 { parameterSet.gamma1 }
  private var gamma2: UInt32 { (prime - 1) / parameterSet.gamma2Divisor }
  private var beta: UInt32 { parameterSet.beta }
  private var omega: Int { parameterSet.omega }
  private var tau: Int { parameterSet.tau }
  private var roots: [UInt32] { MLDSAArithmeticConstants.roots }

  struct GeneratedKeyPair {
    let publicKey: OwnedBytes
    let expandedPublicKey: MLDSAExpandedPublicKey
    let expandedPrivateKey: MLDSAExpandedPrivateKey
  }

  private struct DecodedPrivateKey {
    var rho: ContiguousArray<UInt8>
    var key: ContiguousArray<UInt8>
    var publicKeyHash: ContiguousArray<UInt8>
    var s1NTT: Coefficients
    var s2NTT: Coefficients
    var t0NTT: Coefficients

    mutating func erase() {
      Self.erase(&key)
      Self.erase(&s1NTT)
      Self.erase(&s2NTT)
      Self.erase(&t0NTT)
    }

    private static func erase(_ bytes: inout ContiguousArray<UInt8>) {
      bytes.withUnsafeMutableBufferPointer { buffer in
        guard let pointer = buffer.baseAddress else { return }
        SecureWipe.erase(
          UnsafeMutableRawPointer(pointer),
          byteCount: buffer.count
        )
      }
    }

    private static func erase(_ coefficients: inout Coefficients) {
      coefficients.withUnsafeMutableBufferPointer { buffer in
        guard let pointer = buffer.baseAddress else { return }
        SecureWipe.eraseUInt32Words(
          pointer,
          wordCount: buffer.count
        )
      }
    }
  }

  private struct SigningWorkspace: ~Copyable {
    private let yOffset: Int
    private let wOffset: Int
    private let reusableVectorOffset: Int
    private let challengeOffset: Int
    private let cs1Offset: Int
    private let cs2Offset: Int
    private let zOffset: Int
    private let hintOffset: Int
    private let coefficientCount: Int
    private let maskByteCount: Int
    private let coefficientByteCount: Int
    private let allocationByteCount: Int
    private let allocation: UnsafeMutableRawPointer
    private let pointer: UnsafeMutablePointer<UInt32>
    private let maskBytes: UnsafeMutablePointer<UInt8>

    // Unsafe ownership invariants:
    // - this noncopyable value uniquely owns coefficientCount initialized words;
    // - every region below is in bounds and pairwise disjoint;
    // - pointers are lent only to the synchronous nonescaping closure;
    // - no pointer crosses a Sendable boundary or outlives this owner;
    // - deinit volatile-erases all secret intermediates before exactly-once release.
    init(parameterSet: MLDSAParameterSet) {
      let degree = MLDSAArithmeticConstants.degree
      yOffset = 0
      wOffset = parameterSet.l * degree
      reusableVectorOffset = wOffset + parameterSet.k * degree
      challengeOffset = reusableVectorOffset + parameterSet.k * degree
      cs1Offset = challengeOffset + degree
      cs2Offset = cs1Offset + parameterSet.l * degree
      zOffset = cs2Offset + parameterSet.k * degree
      hintOffset = zOffset + parameterSet.l * degree
      coefficientCount = hintOffset + parameterSet.k * degree
      maskByteCount = 2 * parameterSet.maskPolynomialByteCount
      coefficientByteCount = coefficientCount * MemoryLayout<UInt32>.stride
      allocationByteCount = coefficientByteCount + maskByteCount
      precondition(allocationByteCount.isMultiple(of: MemoryLayout<UInt64>.stride))
      let allocation = UnsafeMutableRawPointer.allocate(
        byteCount: allocationByteCount,
        alignment: MemoryLayout<UInt64>.alignment
      )
      self.allocation = allocation
      pointer = allocation.bindMemory(
        to: UInt32.self,
        capacity: coefficientCount
      )
      pointer.initialize(repeating: 0, count: coefficientCount)
      maskBytes = allocation.advanced(by: coefficientByteCount).bindMemory(
        to: UInt8.self,
        capacity: maskByteCount
      )
      maskBytes.initialize(repeating: 0, count: maskByteCount)
    }

    borrowing func withBuffers<Result, Failure: Error>(
      _ body: (
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt32>,
        UnsafeMutablePointer<UInt8>
      ) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try body(
        pointer.advanced(by: yOffset),
        pointer.advanced(by: wOffset),
        pointer.advanced(by: reusableVectorOffset),
        pointer.advanced(by: challengeOffset),
        pointer.advanced(by: cs1Offset),
        pointer.advanced(by: cs2Offset),
        pointer.advanced(by: zOffset),
        pointer.advanced(by: hintOffset),
        maskBytes
      )
    }

    deinit {
      SecureWipe.eraseUInt64Words(
        allocation,
        wordCount: allocationByteCount / MemoryLayout<UInt64>.stride
      )
      pointer.deinitialize(count: coefficientCount)
      maskBytes.deinitialize(count: maskByteCount)
      allocation.deallocate()
    }
  }

  func keyGenerate(seed: Span<UInt8>) throws(MLDSAError) -> GeneratedKeyPair {
    precondition(seed.count == 32)
    var expandedSeed = try shake256(outputByteCount: 128) { sponge throws(MLDSAError) in
      try absorb(seed, into: &sponge)
      try absorbByte(UInt8(k), into: &sponge)
      try absorbByte(UInt8(l), into: &sponge)
    }
    defer { wipe(&expandedSeed) }

    let rho = copy(expandedSeed.span.extracting(0..<32))
    var sigma = copy(expandedSeed.span.extracting(32..<96))
    defer { wipe(&sigma) }
    var secretKey = copy(expandedSeed.span.extracting(96..<128))
    defer { wipe(&secretKey) }

    var s1 = try expandShort(seed: sigma.span, start: 0, count: l)
    var s2 = try expandShort(seed: sigma.span, start: l, count: k)
    defer {
      wipe(&s1)
      wipe(&s2)
    }
    var derived = try derivePublic(rho: rho.span, s1: &s1, s2: s2)
    defer { wipe(&derived.t0) }

    var publicBytes = ContiguousArray<UInt8>(
      repeating: 0,
      count: parameterSet.publicKeyByteCount
    )
    encodePublicKey(rho: rho.span, t1: derived.t1, into: &publicBytes)
    let publicKeyHash = try shake256(
      outputByteCount: 64,
      absorbing: publicBytes.span
    )

    precondition(publicBytes.count == parameterSet.publicKeyByteCount)
    nttVector(&s2, polynomialCount: k)
    nttVector(&derived.t0, polynomialCount: k)
    let expandedKey = try secretBytes(copying: secretKey.span)
    let expandedPrivateKey = MLDSAExpandedPrivateKey(
      parameterSet: parameterSet,
      key: consume expandedKey,
      takingS1NTT: &s1,
      takingS2NTT: &s2,
      takingT0NTT: &derived.t0
    )
    let expandedPublicKey = MLDSAExpandedPublicKey(
      parameterSet: parameterSet,
      encoded: publicBytes.span,
      publicKeyHash: publicKeyHash.span,
      t1: derived.t1.span
    )
    return GeneratedKeyPair(
      publicKey: OwnedBytes(consuming: publicBytes),
      expandedPublicKey: expandedPublicKey,
      expandedPrivateKey: expandedPrivateKey
    )
  }

  func standardPrivateKeyRepresentation(
    privateKey: borrowing MLDSAExpandedPrivateKey,
    publicKey: borrowing MLDSAExpandedPublicKey
  ) throws(MLDSAError) -> SecretBytes {
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(parameterSet.privateKeyByteCount)
    defer { wipe(&encoded) }
    try privateKey.withMaterial {
      key, s1NTT, s2NTT, t0NTT throws(MLDSAError) in
      try publicKey.withBaseMaterial {
        rho, publicKeyHash, _ throws(MLDSAError) in
        var s1 = coefficients(copying: s1NTT, count: l * degree)
        var s2 = coefficients(copying: s2NTT, count: k * degree)
        var t0 = coefficients(copying: t0NTT, count: k * degree)
        defer {
          wipe(&s1)
          wipe(&s2)
          wipe(&t0)
        }
        inverseNTTVector(&s1, polynomialCount: l)
        inverseNTTVector(&s2, polynomialCount: k)
        inverseNTTVector(&t0, polynomialCount: k)
        cancelInverseNTTScale(&s1)
        cancelInverseNTTScale(&s2)
        cancelInverseNTTScale(&t0)

        var encodedS1 = encodeSigned(
          s1,
          polynomialCount: l,
          bits: parameterSet.shortCoefficientBitCount,
          maximum: eta
        )
        var encodedS2 = encodeSigned(
          s2,
          polynomialCount: k,
          bits: parameterSet.shortCoefficientBitCount,
          maximum: eta
        )
        var encodedT0 = encodeSigned(
          t0,
          polynomialCount: k,
          bits: 13,
          maximum: 1 << 12
        )
        defer {
          wipe(&encodedS1)
          wipe(&encodedS2)
          wipe(&encodedT0)
        }
        append(rho, to: &encoded)
        append(key, to: &encoded)
        append(publicKeyHash, to: &encoded)
        append(encodedS1.span, to: &encoded)
        append(encodedS2.span, to: &encoded)
        append(encodedT0.span, to: &encoded)
      }
    }
    precondition(encoded.count == parameterSet.privateKeyByteCount)
    return try secretBytes(copying: encoded.span)
  }

  func validatePrivateKeyAndDerivePublicKey(
    _ encoded: Span<UInt8>
  ) throws(MLDSAError) -> (
    OwnedBytes,
    MLDSAExpandedPublicKey,
    MLDSAExpandedPrivateKey
  ) {
    var decoded = try decodePrivateKey(encoded)
    defer { decoded.erase() }

    var s1 = decoded.s1NTT
    var s2 = decoded.s2NTT
    inverseNTTVector(&s1, polynomialCount: l)
    inverseNTTVector(&s2, polynomialCount: k)
    cancelInverseNTTScale(&s1)
    cancelInverseNTTScale(&s2)
    defer {
      wipe(&s1)
      wipe(&s2)
    }

    var derived = try derivePublic(rho: decoded.rho.span, s1: &s1, s2: s2)
    defer { wipe(&derived.t0) }
    var encodedT0 = encodeSigned(
      derived.t0,
      polynomialCount: k,
      bits: 13,
      maximum: 1 << 12
    )
    defer { wipe(&encodedT0) }
    let receivedT0 = encoded.extracting(
      parameterSet.privateT0Offset..<parameterSet.privateKeyByteCount
    )
    guard ConstantTime.equal(encodedT0.span, receivedT0) else {
      throw .invalidPrivateKeyEncoding
    }

    var publicBytes = ContiguousArray<UInt8>(
      repeating: 0,
      count: parameterSet.publicKeyByteCount
    )
    encodePublicKey(rho: decoded.rho.span, t1: derived.t1, into: &publicBytes)
    let expectedHash = try shake256(outputByteCount: 64, absorbing: publicBytes.span)
    guard ConstantTime.equal(expectedHash.span, decoded.publicKeyHash.span) else {
      throw .invalidPrivateKeyEncoding
    }
    let expandedPrivateKey = try MLDSAExpandedPrivateKey(
      parameterSet: parameterSet,
      key: decoded.key.span,
      s1NTT: decoded.s1NTT.span,
      s2NTT: decoded.s2NTT.span,
      t0NTT: decoded.t0NTT.span
    )
    let expandedPublicKey = MLDSAExpandedPublicKey(
      parameterSet: parameterSet,
      encoded: publicBytes.span,
      publicKeyHash: expectedHash.span,
      t1: derived.t1.span
    )
    return (
      OwnedBytes(consuming: publicBytes),
      expandedPublicKey,
      expandedPrivateKey
    )
  }

  func expandPublicKey(
    _ encoded: Span<UInt8>
  ) throws(MLDSAError) -> MLDSAExpandedPublicKey {
    precondition(encoded.count == parameterSet.publicKeyByteCount)
    let t1 = decodeUnsigned(
      encoded.extracting(32..<parameterSet.publicKeyByteCount),
      polynomialCount: k,
      bits: 10
    )
    let publicKeyHash = try shake256(outputByteCount: 64, absorbing: encoded)
    return MLDSAExpandedPublicKey(
      parameterSet: parameterSet,
      encoded: encoded,
      publicKeyHash: publicKeyHash.span,
      t1: t1.span
    )
  }

  func expandPublicMaterial(
    rho: Span<UInt8>,
    t1: Span<UInt32>
  ) throws(MLDSAError) -> MLDSAExpandedPublicMaterial {
    precondition(rho.count == 32)
    precondition(t1.count == k * degree)
    var t1NTT = Coefficients(repeating: 0, count: t1.count)
    var index = 0
    while index < t1.count {
      t1NTT[index] = t1[index]
      index += 1
    }
    scalePower2RoundVector(&t1NTT)
    nttVector(&t1NTT, polynomialCount: k)
    let matrix = try expandMatrix(rho: rho)
    return MLDSAExpandedPublicMaterial(
      parameterSet: parameterSet,
      t1NTT: t1NTT.span,
      matrix: matrix.span
    )
  }

  func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    privateKey: borrowing MLDSAExpandedPrivateKey,
    publicKey: borrowing MLDSAExpandedPublicKey,
    randomizer: Span<UInt8>
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    var signature = ContiguousArray<UInt8>(
      repeating: 0,
      count: parameterSet.signatureByteCount
    )
    var output = signature.mutableSpan
    try sign(
      message: message,
      context: context,
      privateKey: privateKey,
      publicKey: publicKey,
      randomizer: randomizer,
      into: &output
    )
    return signature
  }

  func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    privateKey: borrowing MLDSAExpandedPrivateKey,
    publicKey: borrowing MLDSAExpandedPublicKey,
    randomizer: Span<UInt8>,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    precondition(signature.count == parameterSet.signatureByteCount)
    try privateKey.withMaterial {
      key, s1NTT, s2NTT, t0NTT throws(MLDSAError) in
      try publicKey.withMaterial {
        _, publicKeyHash, _, matrix throws(MLDSAError) in
        try signExpanded(
          message: message,
          context: context,
          key: key,
          publicKeyHash: publicKeyHash,
          s1NTT: s1NTT,
          s2NTT: s2NTT,
          t0NTT: t0NTT,
          matrix: matrix,
          randomizer: randomizer,
          into: &signature
        )
      }
    }
  }

  private func signExpanded(
    message: Span<UInt8>,
    context: Span<UInt8>,
    key: Span<UInt8>,
    publicKeyHash: Span<UInt8>,
    s1NTT: UnsafePointer<UInt32>,
    s2NTT: UnsafePointer<UInt32>,
    t0NTT: UnsafePointer<UInt32>,
    matrix: UnsafePointer<UInt32>,
    randomizer: Span<UInt8>,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    precondition(randomizer.count == 32)

    var mu = try messageRepresentative(
      publicKeyHash: publicKeyHash,
      message: message,
      context: context
    )
    defer { wipe(&mu) }
    var rhoPrime = try shake256(outputByteCount: 64) { sponge throws(MLDSAError) in
      try absorb(key, into: &sponge)
      try absorb(randomizer, into: &sponge)
      try absorb(mu.span, into: &sponge)
    }
    defer { wipe(&rhoPrime) }

    let workspace = SigningWorkspace(parameterSet: parameterSet)
    try workspace.withBuffers {
      y, w, reusableVector, challenge, cs1, cs2, z, hint, maskBytes throws(MLDSAError) in
      var kappa = 0
      while kappa <= 65_535 - l {
        try expandMask(
          seed: rhoPrime.span,
          startingAt: kappa,
          into: y,
          scratch: maskBytes
        )
        copyCoefficients(
          from: UnsafePointer(y),
          to: cs1,
          count: l * degree
        )
        nttVector(cs1, polynomialCount: l)
        matrixMultiply(matrix, vector: cs1, into: w)
        inverseNTTVector(w, polynomialCount: k)
        highBitsVector(w, into: reusableVector, count: k * degree)
        var encodedW1 = encodeUnsigned(
          UnsafePointer(reusableVector),
          coefficientCount: k * degree,
          bits: parameterSet.highBitsCoefficientBitCount
        )
        defer { wipe(&encodedW1) }
        var challengeHash = try shake256(outputByteCount: parameterSet.challengeByteCount) {
          sponge throws(MLDSAError) in
          try absorb(mu.span, into: &sponge)
          try absorb(encodedW1.span, into: &sponge)
        }
        defer { wipe(&challengeHash) }
        try sampleInBall(seed: challengeHash.span, into: challenge)
        nttPolynomial(challenge)

        vectorMultiplyScalar(
          s1NTT,
          scalar: challenge,
          into: cs1,
          polynomialCount: l
        )
        inverseNTTVector(cs1, polynomialCount: l)
        vectorMultiplyScalar(
          s2NTT,
          scalar: challenge,
          into: cs2,
          polynomialCount: k
        )
        inverseNTTVector(cs2, polynomialCount: k)
        addVectors(y, cs1, into: z, count: l * degree)
        subtractVectors(w, cs2, into: reusableVector, count: k * degree)
        lowBitsVector(reusableVector, count: k * degree)

        if maximumModPrime(z, count: l * degree) >= gamma1 - beta
          || maximumSigned(reusableVector, count: k * degree) >= gamma2 - beta
        {
          kappa += l
          continue
        }

        vectorMultiplyScalar(
          t0NTT,
          scalar: challenge,
          into: reusableVector,
          polynomialCount: k
        )
        inverseNTTVector(reusableVector, polynomialCount: k)
        makeHintVector(
          ct0: reusableVector,
          cs2: cs2,
          w: w,
          into: hint,
          count: k * degree
        )
        if maximumModPrime(reusableVector, count: k * degree) >= gamma2
          || countOnes(hint, count: k * degree) > omega
        {
          kappa += l
          continue
        }

        signature.withUnsafeMutableBufferPointer { output in
          let destination = output.baseAddress.unsafelyUnwrapped
          copyBytes(
            challengeHash.span,
            to: destination,
            at: 0
          )
          bitPack(
            UnsafePointer(z),
            coefficientCount: l * degree,
            bits: parameterSet.maskCoefficientBitCount,
            maximum: gamma1,
            into: destination.advanced(by: parameterSet.signatureZOffset)
          )
          encodeHint(
            hint,
            into: destination.advanced(by: parameterSet.signatureHintOffset)
          )
        }
        return
      }
      throw .inputTooLong
    }
  }

  func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKey: borrowing MLDSAExpandedPublicKey
  ) throws(MLDSAError) -> Bool {
    try publicKey.withMaterial {
      _, publicKeyHash, t1NTT, matrix throws(MLDSAError) in
      try verifyExpanded(
        signature: signature,
        message: message,
        context: context,
        publicKeyHash: publicKeyHash,
        t1NTT: t1NTT,
        matrix: matrix
      )
    }
  }

  private func verifyExpanded(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    publicKeyHash: Span<UInt8>,
    t1NTT: UnsafePointer<UInt32>,
    matrix: UnsafePointer<UInt32>
  ) throws(MLDSAError) -> Bool {
    precondition(signature.count == parameterSet.signatureByteCount)
    guard var decodedSignature = decodeSignature(signature) else {
      return false
    }
    if maximumModPrime(decodedSignature.z) >= gamma1 - beta {
      return false
    }

    let mu = try messageRepresentative(
      publicKeyHash: publicKeyHash,
      message: message,
      context: context
    )
    var c = try sampleInBall(seed: decodedSignature.challenge.span)
    nttPolynomial(&c, base: 0)
    // The decoded z owner becomes the NTT workspace. Keeping a second array
    // here would trigger a 5,120-byte COW copy on every verification.
    nttVector(&decodedSignature.z, polynomialCount: l)
    var az = Coefficients(repeating: 0, count: k * degree)
    decodedSignature.z.withUnsafeBufferPointer { vector in
      az.withUnsafeMutableBufferPointer { output in
        matrixMultiply(
          matrix,
          vector: vector.baseAddress.unsafelyUnwrapped,
          into: output.baseAddress.unsafelyUnwrapped
        )
      }
    }
    var product = Coefficients(repeating: 0, count: k * degree)
    c.withUnsafeBufferPointer { scalar in
      product.withUnsafeMutableBufferPointer { output in
        vectorMultiplyScalar(
          t1NTT,
          scalar: scalar.baseAddress.unsafelyUnwrapped,
          into: output.baseAddress.unsafelyUnwrapped,
          polynomialCount: k
        )
      }
    }
    subtractVector(product, from: &az)
    inverseNTTVector(&az, polynomialCount: k)
    useHintVector(decodedSignature.hint, value: &az)
    let encodedW1 = encodeUnsigned(
      az,
      polynomialCount: k,
      bits: parameterSet.highBitsCoefficientBitCount
    )
    let expectedChallenge = try shake256(outputByteCount: parameterSet.challengeByteCount) {
      sponge throws(MLDSAError) in
      try absorb(mu.span, into: &sponge)
      try absorb(encodedW1.span, into: &sponge)
    }
    return ConstantTime.equal(expectedChallenge.span, decodedSignature.challenge.span)
  }

  private func derivePublic(
    rho: Span<UInt8>,
    s1: inout Coefficients,
    s2: Coefficients
  ) throws(MLDSAError) -> (
    t1: Coefficients,
    t0: Coefficients
  ) {
    let matrix = try expandMatrix(rho: rho)
    nttVector(&s1, polynomialCount: l)
    var t = Coefficients(repeating: 0, count: k * degree)
    matrixMultiply(matrix.span, vector: s1.span, into: &t)
    inverseNTTVector(&t, polynomialCount: k)
    addVector(s2, into: &t)
    var t1 = Coefficients(repeating: 0, count: k * degree)
    var t0 = Coefficients(repeating: 0, count: k * degree)
    power2RoundVector(t, high: &t1, low: &t0)
    return (t1, t0)
  }

  private func decodePrivateKey(
    _ encoded: Span<UInt8>
  ) throws(MLDSAError) -> DecodedPrivateKey {
    guard encoded.count == parameterSet.privateKeyByteCount else {
      throw .invalidPrivateKeyLength(
        expected: parameterSet.privateKeyByteCount,
        actual: encoded.count
      )
    }
    let rho = copy(encoded.extracting(0..<32))
    var key = copy(encoded.extracting(32..<64))
    let publicKeyHash = copy(encoded.extracting(64..<128))
    guard
      var s1 = decodeSigned(
        encoded.extracting(parameterSet.privateS1Offset..<parameterSet.privateS2Offset),
        polynomialCount: l,
        bits: parameterSet.shortCoefficientBitCount,
        maximum: eta,
        validateRange: true
      )
    else {
      wipe(&key)
      throw .invalidPrivateKeyEncoding
    }
    guard
      var s2 = decodeSigned(
        encoded.extracting(parameterSet.privateS2Offset..<parameterSet.privateT0Offset),
        polynomialCount: k,
        bits: parameterSet.shortCoefficientBitCount,
        maximum: eta,
        validateRange: true
      )
    else {
      wipe(&key)
      wipe(&s1)
      throw .invalidPrivateKeyEncoding
    }
    guard
      var t0 = decodeSigned(
        encoded.extracting(parameterSet.privateT0Offset..<parameterSet.privateKeyByteCount),
        polynomialCount: k,
        bits: 13,
        maximum: 1 << 12,
        validateRange: false
      )
    else {
      wipe(&key)
      wipe(&s1)
      wipe(&s2)
      throw .invalidPrivateKeyEncoding
    }
    nttVector(&s1, polynomialCount: l)
    nttVector(&s2, polynomialCount: k)
    nttVector(&t0, polynomialCount: k)
    return DecodedPrivateKey(
      rho: rho,
      key: key,
      publicKeyHash: publicKeyHash,
      s1NTT: s1,
      s2NTT: s2,
      t0NTT: t0
    )
  }

  private struct DecodedSignature {
    let challenge: ContiguousArray<UInt8>
    var z: Coefficients
    let hint: Coefficients
  }

  private func decodeSignature(_ encoded: Span<UInt8>) -> DecodedSignature? {
    let challenge = copy(encoded.extracting(0..<parameterSet.challengeByteCount))
    guard
      let z = decodeSigned(
        encoded.extracting(parameterSet.signatureZOffset..<parameterSet.signatureHintOffset),
        polynomialCount: l,
        bits: parameterSet.maskCoefficientBitCount,
        maximum: gamma1,
        validateRange: false
      ),
      let hint = decodeHint(
        encoded.extracting(parameterSet.signatureHintOffset..<parameterSet.signatureByteCount)
      )
    else {
      return nil
    }
    return DecodedSignature(challenge: challenge, z: z, hint: hint)
  }

  private func messageRepresentative(
    publicKeyHash: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try shake256(outputByteCount: 64) { sponge throws(MLDSAError) in
      try absorb(publicKeyHash, into: &sponge)
      try absorbByte(0, into: &sponge)
      try absorbByte(UInt8(context.count), into: &sponge)
      try absorb(context, into: &sponge)
      try absorb(message, into: &sponge)
    }
  }

  private func expandMatrix(
    rho: Span<UInt8>
  ) throws(MLDSAError) -> Coefficients {
    var matrix = Coefficients(repeating: 0, count: k * l * degree)
    var sampler = KeccakX2Core(sensitivity: .publicData)
    try matrix.withUnsafeMutableBufferPointer { buffer throws(MLDSAError) in
      let pointer = buffer.baseAddress.unsafelyUnwrapped
      var polynomial = 0
      while polynomial < k * l {
        let firstRow = polynomial / l
        let firstColumn = polynomial % l
        let second = polynomial + 1
        let secondRow = second / l
        let secondColumn = second % l
        sampler.reset(
          seed: rho,
          firstSuffix: (UInt8(firstColumn), UInt8(firstRow)),
          secondSuffix: (UInt8(secondColumn), UInt8(secondRow))
        )
        sampler.sampleMLDSAMatrix(
          first: pointer.advanced(by: polynomial * degree),
          second: pointer.advanced(by: second * degree)
        )
        polynomial += 2
      }
    }
    return matrix
  }

  private func expandShort(
    seed: Span<UInt8>,
    start: Int,
    count: Int
  ) throws(MLDSAError) -> Coefficients {
    var vector = Coefficients(repeating: 0, count: count * degree)
    var sampler = KeccakX2Core(sensitivity: .secret)
    var polynomial = 0
    try vector.withUnsafeMutableBufferPointer { buffer throws(MLDSAError) in
      let pointer = buffer.baseAddress.unsafelyUnwrapped
      while polynomial + 1 < count {
        sampler.reset(
          mlDSASecretSeed: seed,
          firstNonce: UInt16(start + polynomial),
          secondNonce: UInt16(start + polynomial + 1)
        )
        sampler.sampleMLDSAShort(
          first: pointer.advanced(by: polynomial * degree),
          second: pointer.advanced(by: (polynomial + 1) * degree),
          eta: eta
        )
        polynomial += 2
      }
    }
    if polynomial < count {
      let nonce = start + polynomial
      var sponge = KeccakCore(rateByteCount: 136, domainSeparator: 0x1F)
      do {
        try absorb(seed, into: &sponge)
        try absorbByte(UInt8(nonce), into: &sponge)
        try absorbByte(0, into: &sponge)
      } catch {
        sponge.erase()
        throw error
      }
      var done = 0
      var block = ContiguousArray<UInt8>(repeating: 0, count: 136)
      defer { wipe(&block) }
      let base = polynomial * degree
      while done < degree {
        var output = block.mutableSpan
        sponge.squeeze(into: &output)
        var offset = 0
        while offset < block.count && done < degree {
          let low = UInt32(block[offset] & 0x0F)
          let high = UInt32(block[offset] >> 4)
          if let coefficient = shortCoefficient(low) {
            vector[base + done] = coefficient
            done += 1
          }
          if done < degree, let coefficient = shortCoefficient(high) {
            vector[base + done] = coefficient
            done += 1
          }
          offset += 1
        }
      }
      sponge.erase()
    }
    return vector
  }

  @inline(__always)
  private func shortCoefficient(_ nibble: UInt32) -> UInt32? {
    let limit: UInt32 = eta == 4 ? 9 : 15
    guard nibble < limit else { return nil }
    let reduced = eta == 4 ? nibble : nibble - 5 * ((205 * nibble) >> 10)
    return modSubtract(eta, reduced)
  }

  private func expandMask(
    seed: Span<UInt8>,
    startingAt start: Int,
    into vector: UnsafeMutablePointer<UInt32>,
    scratch: UnsafeMutablePointer<UInt8>
  ) throws(MLDSAError) {
    var sampler = KeccakX2Core(sensitivity: .secret)
    var polynomial = 0
    while polynomial + 1 < l {
      sampler.reset(
        mlDSASecretSeed: seed,
        firstNonce: UInt16(start + polynomial),
        secondNonce: UInt16(start + polynomial + 1)
      )
      sampler.squeezeMLDSAMasks(
        first: scratch,
        second: scratch.advanced(by: parameterSet.maskPolynomialByteCount),
        byteCount: parameterSet.maskPolynomialByteCount
      )
      let firstEncoded = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: scratch,
          count: parameterSet.maskPolynomialByteCount
        )
      )
      let secondEncoded = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: scratch.advanced(by: parameterSet.maskPolynomialByteCount),
          count: parameterSet.maskPolynomialByteCount
        )
      )
      guard
        decodeSigned(
          firstEncoded,
          into: vector.advanced(by: polynomial * degree),
          valueCount: degree,
          bits: parameterSet.maskCoefficientBitCount,
          maximum: gamma1,
          validateRange: false
        ),
        decodeSigned(
          secondEncoded,
          into: vector.advanced(by: (polynomial + 1) * degree),
          valueCount: degree,
          bits: parameterSet.maskCoefficientBitCount,
          maximum: gamma1,
          validateRange: false
        )
      else {
        preconditionFailure("ML-DSA mask decoding cannot fail")
      }
      polynomial += 2
    }
    if polynomial < l {
      let nonce = UInt16(start + polynomial)
      var sponge = KeccakCore(rateByteCount: 136, domainSeparator: 0x1F)
      do {
        try absorb(seed, into: &sponge)
        try absorbByte(UInt8(truncatingIfNeeded: nonce), into: &sponge)
        try absorbByte(UInt8(truncatingIfNeeded: nonce >> 8), into: &sponge)
      } catch {
        sponge.erase()
        throw error
      }
      var output = MutableSpan(
        _unsafeStart: scratch,
        count: parameterSet.maskPolynomialByteCount
      )
      sponge.squeeze(into: &output)
      sponge.erase()
      let encoded = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: scratch,
          count: parameterSet.maskPolynomialByteCount
        )
      )
      guard
        decodeSigned(
          encoded,
          into: vector.advanced(by: polynomial * degree),
          valueCount: degree,
          bits: parameterSet.maskCoefficientBitCount,
          maximum: gamma1,
          validateRange: false
        )
      else {
        preconditionFailure("ML-DSA mask decoding cannot fail")
      }
    }
  }

  private func sampleInBall(
    seed: Span<UInt8>
  ) throws(MLDSAError) -> Coefficients {
    var polynomial = Coefficients(repeating: 0, count: degree)
    try polynomial.withUnsafeMutableBufferPointer { buffer throws(MLDSAError) in
      try sampleInBall(
        seed: seed,
        into: buffer.baseAddress.unsafelyUnwrapped
      )
    }
    return polynomial
  }

  private func sampleInBall(
    seed: Span<UInt8>,
    into polynomial: UnsafeMutablePointer<UInt32>
  ) throws(MLDSAError) {
    var sponge = KeccakCore(rateByteCount: 136, domainSeparator: 0x1F)
    do {
      try absorb(seed, into: &sponge)
    } catch {
      sponge.erase()
      throw error
    }
    var block = ContiguousArray<UInt8>(repeating: 0, count: 136)
    var output = block.mutableSpan
    sponge.squeeze(into: &output)
    var signs: UInt64 = 0
    var byteIndex = 0
    while byteIndex < 8 {
      signs |= UInt64(block[byteIndex]) << UInt64(byteIndex * 8)
      byteIndex += 1
    }
    var offset = 8
    polynomial.update(repeating: 0, count: degree)
    var index = degree - tau
    while index < degree {
      var selected: Int
      while true {
        if offset == block.count {
          var next = block.mutableSpan
          sponge.squeeze(into: &next)
          offset = 0
        }
        selected = Int(block[offset])
        offset += 1
        if selected <= index { break }
      }
      polynomial[index] = polynomial[selected]
      polynomial[selected] = modSubtract(1, UInt32(2 * (signs & 1)))
      signs >>= 1
      index += 1
    }
    sponge.erase()
  }

  private func power2RoundVector(
    _ input: Coefficients,
    high: inout Coefficients,
    low: inout Coefficients
  ) {
    precondition(high.count == input.count && low.count == input.count)
    input.withUnsafeBufferPointer { inputBuffer in
      high.withUnsafeMutableBufferPointer { highBuffer in
        low.withUnsafeMutableBufferPointer { lowBuffer in
          let inputPointer = inputBuffer.baseAddress.unsafelyUnwrapped
          let highPointer = highBuffer.baseAddress.unsafelyUnwrapped
          let lowPointer = lowBuffer.baseAddress.unsafelyUnwrapped
          let dropped = SIMD4<UInt32>(repeating: UInt32(droppedBits))
          let modulus = SIMD4<UInt32>(repeating: 1 << droppedBits)
          let midpoint = SIMD4<UInt32>(repeating: 1 << (droppedBits - 1))
          let one = SIMD4<UInt32>(repeating: 1)
          var index = 0
          while index + 4 <= input.count {
            let value = loadSIMD4(inputPointer.advanced(by: index))
            var r1 = value &>> dropped
            var r0 = value &- (r1 &<< dropped)
            let adjustedR0 = modSubtract(r0, modulus)
            let adjustedR1 = r1 &+ one
            let mask =
              SIMD4<UInt32>(repeating: 0)
              &- ((midpoint &- r0) &>> SIMD4<UInt32>(repeating: 31))
            r0 = (mask & adjustedR0) | (~mask & r0)
            r1 = (mask & adjustedR1) | (~mask & r1)
            storeSIMD4(r1, to: highPointer.advanced(by: index))
            storeSIMD4(r0, to: lowPointer.advanced(by: index))
            index += 4
          }
        }
      }
    }
  }

  private func scalePower2RoundVector(_ value: inout Coefficients) {
    var index = 0
    while index < value.count {
      value[index] <<= UInt32(droppedBits)
      index += 1
    }
  }

  private func highBitsVector(
    _ input: Coefficients,
    into output: inout Coefficients
  ) {
    var index = 0
    while index < input.count {
      output[index] = highBits(input[index])
      index += 1
    }
  }

  private func highBitsVector(
    _ input: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    var index = 0
    while index < count {
      output[index] = highBits(input[index])
      index += 1
    }
  }

  private func lowBitsVector(
    _ input: Coefficients,
    into output: inout Coefficients
  ) {
    var index = 0
    while index < input.count {
      output[index] = UInt32(bitPattern: lowBits(input[index]))
      index += 1
    }
  }

  private func lowBitsVector(
    _ value: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    var index = 0
    while index < count {
      value[index] = UInt32(bitPattern: lowBits(value[index]))
      index += 1
    }
  }

  private func highBits(_ value: UInt32) -> UInt32 {
    var result = (value + 127) >> 7
    if parameterSet.gamma2Divisor == 32 {
      result = (result * 1_025 + (1 << 21)) >> 22
      return result & 15
    }
    precondition(parameterSet.gamma2Divisor == 88)
    result = (result * 11_275 + (1 << 23)) >> 24
    let wrapMask = UInt32(bitPattern: (Int32(43) - Int32(result)) >> 31)
    return result ^ (wrapMask & result)
  }

  private func lowBits(_ value: UInt32) -> Int32 {
    let high = highBits(value)
    var low = Int32(value) - Int32(high * 2 * gamma2)
    low -= ((Int32(halfPrime) - low) >> 31) & Int32(prime)
    return low
  }

  private func makeHintVector(
    ct0: Coefficients,
    cs2: Coefficients,
    w: Coefficients,
    into output: inout Coefficients
  ) {
    var index = 0
    while index < output.count {
      let rPlusZ = modSubtract(w[index], cs2[index])
      let r = reduceOnce(rPlusZ + ct0[index])
      let difference = highBits(r) ^ highBits(rPlusZ)
      output[index] = (difference | (0 &- difference)) >> 31
      index += 1
    }
  }

  private func makeHintVector(
    ct0: UnsafePointer<UInt32>,
    cs2: UnsafePointer<UInt32>,
    w: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    var index = 0
    while index < count {
      let rPlusZ = modSubtract(w[index], cs2[index])
      let r = reduceOnce(rPlusZ + ct0[index])
      let difference = highBits(r) ^ highBits(rPlusZ)
      output[index] = (difference | (0 &- difference)) >> 31
      index += 1
    }
  }

  private func useHintVector(
    _ hint: Coefficients,
    value: inout Coefficients
  ) {
    precondition(hint.count == value.count)
    hint.withUnsafeBufferPointer { hintBuffer in
      value.withUnsafeMutableBufferPointer { valueBuffer in
        let hintPointer = hintBuffer.baseAddress.unsafelyUnwrapped
        let valuePointer = valueBuffer.baseAddress.unsafelyUnwrapped
        var index = 0
        while index < valueBuffer.count {
          let coefficient = valuePointer[index]
          let high = highBits(coefficient)
          if hintPointer[index] == 0 {
            valuePointer[index] = high
          } else if parameterSet.gamma2Divisor == 32 {
            if lowBits(coefficient) > 0 {
              valuePointer[index] = (high + 1) & 15
            } else {
              valuePointer[index] = (high &- 1) & 15
            }
          } else if lowBits(coefficient) > 0 {
            valuePointer[index] = high == 43 ? 0 : high + 1
          } else {
            valuePointer[index] = high == 0 ? 43 : high - 1
          }
          index += 1
        }
      }
    }
  }

  private func encodeHint(_ hint: Coefficients) -> ContiguousArray<UInt8> {
    var encoded = ContiguousArray<UInt8>(repeating: 0, count: omega + k)
    var outputIndex = 0
    var polynomial = 0
    while polynomial < k {
      let base = polynomial * degree
      var coefficient = 0
      while coefficient < degree {
        if hint[base + coefficient] != 0 {
          precondition(outputIndex < omega)
          encoded[outputIndex] = UInt8(coefficient)
          outputIndex += 1
        }
        coefficient += 1
      }
      encoded[omega + polynomial] = UInt8(outputIndex)
      polynomial += 1
    }
    return encoded
  }

  private func encodeHint(
    _ hint: UnsafePointer<UInt32>
  ) -> ContiguousArray<UInt8> {
    var encoded = ContiguousArray<UInt8>(repeating: 0, count: omega + k)
    var outputIndex = 0
    var polynomial = 0
    while polynomial < k {
      let base = polynomial * degree
      var coefficient = 0
      while coefficient < degree {
        if hint[base + coefficient] != 0 {
          precondition(outputIndex < omega)
          encoded[outputIndex] = UInt8(coefficient)
          outputIndex += 1
        }
        coefficient += 1
      }
      encoded[omega + polynomial] = UInt8(outputIndex)
      polynomial += 1
    }
    return encoded
  }

  private func encodeHint(
    _ hint: UnsafePointer<UInt32>,
    into encoded: UnsafeMutablePointer<UInt8>
  ) {
    encoded.update(repeating: 0, count: omega + k)
    var outputIndex = 0
    var polynomial = 0
    while polynomial < k {
      let base = polynomial * degree
      var coefficient = 0
      while coefficient < degree {
        if hint[base + coefficient] != 0 {
          precondition(outputIndex < omega)
          encoded[outputIndex] = UInt8(coefficient)
          outputIndex += 1
        }
        coefficient += 1
      }
      encoded[omega + polynomial] = UInt8(outputIndex)
      polynomial += 1
    }
  }

  private func decodeHint(_ encoded: Span<UInt8>) -> Coefficients? {
    precondition(encoded.count == omega + k)
    var hint = Coefficients(repeating: 0, count: k * degree)
    var inputIndex = 0
    var polynomial = 0
    while polynomial < k {
      let limit = Int(encoded[omega + polynomial])
      if limit < inputIndex || limit > omega { return nil }
      var last = -1
      while inputIndex < limit {
        let coefficient = Int(encoded[inputIndex])
        if coefficient <= last { return nil }
        last = coefficient
        hint[polynomial * degree + coefficient] = 1
        inputIndex += 1
      }
      polynomial += 1
    }
    while inputIndex < omega {
      if encoded[inputIndex] != 0 { return nil }
      inputIndex += 1
    }
    return hint
  }

  private func encodeUnsigned(
    _ coefficients: Coefficients,
    polynomialCount: Int,
    bits: Int
  ) -> ContiguousArray<UInt8> {
    precondition(coefficients.count == polynomialCount * degree)
    return bitPack(coefficients, bits: bits) { $0 }
  }

  private func encodePublicKey(
    rho: Span<UInt8>,
    t1: Coefficients,
    into encoded: inout ContiguousArray<UInt8>
  ) {
    precondition(rho.count == 32)
    precondition(t1.count == k * degree)
    precondition(encoded.count == parameterSet.publicKeyByteCount)
    // Unsafe boundary invariants:
    // - encoded owns exactly 32 + (k * degree * 10 / 8) initialized bytes;
    // - rho and t1 are immutable synchronous borrows with validated counts;
    // - four ten-bit coefficients always map to five bounded output bytes;
    // - neither source nor destination pointer escapes either closure.
    encoded.withUnsafeMutableBufferPointer { outputBuffer in
      let output = outputBuffer.baseAddress.unsafelyUnwrapped
      copyBytes(rho, to: output, at: 0)
      t1.withUnsafeBufferPointer { inputBuffer in
        encodeUnsigned10(
          inputBuffer.baseAddress.unsafelyUnwrapped,
          coefficientCount: t1.count,
          into: output.advanced(by: 32)
        )
      }
    }
  }

  @inline(__always)
  private func encodeUnsigned10(
    _ coefficients: UnsafePointer<UInt32>,
    coefficientCount: Int,
    into encoded: UnsafeMutablePointer<UInt8>
  ) {
    precondition(coefficientCount.isMultiple(of: 4))
    var inputIndex = 0
    var outputIndex = 0
    while inputIndex < coefficientCount {
      let first = coefficients[inputIndex]
      let second = coefficients[inputIndex + 1]
      let third = coefficients[inputIndex + 2]
      let fourth = coefficients[inputIndex + 3]
      assert((first | second | third | fourth) < 1_024)
      let packed =
        UInt64(first)
        | (UInt64(second) << 10)
        | (UInt64(third) << 20)
        | (UInt64(fourth) << 30)
      encoded[outputIndex] = UInt8(truncatingIfNeeded: packed)
      encoded[outputIndex + 1] = UInt8(truncatingIfNeeded: packed >> 8)
      encoded[outputIndex + 2] = UInt8(truncatingIfNeeded: packed >> 16)
      encoded[outputIndex + 3] = UInt8(truncatingIfNeeded: packed >> 24)
      encoded[outputIndex + 4] = UInt8(truncatingIfNeeded: packed >> 32)
      inputIndex += 4
      outputIndex += 5
    }
  }

  private func encodeUnsigned(
    _ coefficients: UnsafePointer<UInt32>,
    coefficientCount: Int,
    bits: Int
  ) -> ContiguousArray<UInt8> {
    bitPack(
      coefficients,
      coefficientCount: coefficientCount,
      bits: bits,
      maximum: nil
    )
  }

  private func encodeSigned(
    _ coefficients: Coefficients,
    polynomialCount: Int,
    bits: Int,
    maximum: UInt32
  ) -> ContiguousArray<UInt8> {
    precondition(coefficients.count == polynomialCount * degree)
    return bitPack(coefficients, bits: bits) { modSubtract(maximum, $0) }
  }

  private func encodeSigned(
    _ coefficients: UnsafePointer<UInt32>,
    coefficientCount: Int,
    bits: Int,
    maximum: UInt32
  ) -> ContiguousArray<UInt8> {
    bitPack(
      coefficients,
      coefficientCount: coefficientCount,
      bits: bits,
      maximum: maximum
    )
  }

  private func bitPack(
    _ coefficients: UnsafePointer<UInt32>,
    coefficientCount: Int,
    bits: Int,
    maximum: UInt32?
  ) -> ContiguousArray<UInt8> {
    let byteCount = coefficientCount * bits / 8
    var encoded = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
    var accumulator: UInt64 = 0
    var accumulatorBits = 0
    var outputIndex = 0
    let limit = UInt32(1) << UInt32(bits)
    var index = 0
    while index < coefficientCount {
      let value: UInt32
      if let maximum {
        value = modSubtract(maximum, coefficients[index])
      } else {
        value = coefficients[index]
      }
      precondition(value < limit)
      accumulator |= UInt64(value) << UInt64(accumulatorBits)
      accumulatorBits += bits
      while accumulatorBits >= 8 {
        encoded[outputIndex] = UInt8(truncatingIfNeeded: accumulator)
        outputIndex += 1
        accumulator >>= 8
        accumulatorBits -= 8
      }
      index += 1
    }
    precondition(outputIndex == encoded.count && accumulatorBits == 0)
    return encoded
  }

  private func bitPack(
    _ coefficients: UnsafePointer<UInt32>,
    coefficientCount: Int,
    bits: Int,
    maximum: UInt32?,
    into encoded: UnsafeMutablePointer<UInt8>
  ) {
    let byteCount = coefficientCount * bits / 8
    encoded.update(repeating: 0, count: byteCount)
    var accumulator: UInt64 = 0
    var accumulatorBits = 0
    var outputIndex = 0
    let limit = UInt32(1) << UInt32(bits)
    var index = 0
    while index < coefficientCount {
      let value: UInt32
      if let maximum {
        value = modSubtract(maximum, coefficients[index])
      } else {
        value = coefficients[index]
      }
      precondition(value < limit)
      accumulator |= UInt64(value) << UInt64(accumulatorBits)
      accumulatorBits += bits
      while accumulatorBits >= 8 {
        encoded[outputIndex] = UInt8(truncatingIfNeeded: accumulator)
        outputIndex += 1
        accumulator >>= 8
        accumulatorBits -= 8
      }
      index += 1
    }
    precondition(outputIndex == byteCount && accumulatorBits == 0)
  }

  private func bitPack(
    _ coefficients: Coefficients,
    bits: Int,
    transform: (UInt32) -> UInt32
  ) -> ContiguousArray<UInt8> {
    let byteCount = coefficients.count * bits / 8
    var encoded = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
    var accumulator: UInt64 = 0
    var accumulatorBits = 0
    var outputIndex = 0
    let limit = UInt32(1) << UInt32(bits)
    var index = 0
    while index < coefficients.count {
      let value = transform(coefficients[index])
      precondition(value < limit)
      accumulator |= UInt64(value) << UInt64(accumulatorBits)
      accumulatorBits += bits
      while accumulatorBits >= 8 {
        encoded[outputIndex] = UInt8(truncatingIfNeeded: accumulator)
        outputIndex += 1
        accumulator >>= 8
        accumulatorBits -= 8
      }
      index += 1
    }
    precondition(outputIndex == encoded.count && accumulatorBits == 0)
    return encoded
  }

  private func decodeUnsigned(
    _ encoded: Span<UInt8>,
    polynomialCount: Int,
    bits: Int
  ) -> Coefficients {
    bitUnpack(encoded, valueCount: polynomialCount * degree, bits: bits)
  }

  private func decodeSigned(
    _ encoded: Span<UInt8>,
    polynomialCount: Int,
    bits: Int,
    maximum: UInt32,
    validateRange: Bool
  ) -> Coefficients? {
    let unpacked = bitUnpack(
      encoded,
      valueCount: polynomialCount * degree,
      bits: bits
    )
    var decoded = Coefficients(repeating: 0, count: unpacked.count)
    var index = 0
    while index < unpacked.count {
      let value = unpacked[index]
      if validateRange && value > 2 * maximum { return nil }
      decoded[index] = modSubtract(maximum, value)
      index += 1
    }
    return decoded
  }

  private func decodeSigned(
    _ encoded: Span<UInt8>,
    into output: UnsafeMutablePointer<UInt32>,
    valueCount: Int,
    bits: Int,
    maximum: UInt32,
    validateRange: Bool
  ) -> Bool {
    precondition(encoded.count == valueCount * bits / 8)
    let mask = (UInt64(1) << UInt64(bits)) - 1
    var accumulator: UInt64 = 0
    var accumulatorBits = 0
    var inputIndex = 0
    var outputIndex = 0
    while outputIndex < valueCount {
      while accumulatorBits < bits {
        accumulator |= UInt64(encoded[inputIndex]) << UInt64(accumulatorBits)
        inputIndex += 1
        accumulatorBits += 8
      }
      let value = UInt32(accumulator & mask)
      if validateRange && value > 2 * maximum {
        return false
      }
      output[outputIndex] = modSubtract(maximum, value)
      accumulator >>= UInt64(bits)
      accumulatorBits -= bits
      outputIndex += 1
    }
    return true
  }

  private func bitUnpack(
    _ encoded: Span<UInt8>,
    valueCount: Int,
    bits: Int
  ) -> Coefficients {
    precondition(encoded.count == valueCount * bits / 8)
    var output = Coefficients(repeating: 0, count: valueCount)
    let mask = (UInt64(1) << UInt64(bits)) - 1
    var accumulator: UInt64 = 0
    var accumulatorBits = 0
    var inputIndex = 0
    var outputIndex = 0
    while outputIndex < valueCount {
      while accumulatorBits < bits {
        accumulator |= UInt64(encoded[inputIndex]) << UInt64(accumulatorBits)
        inputIndex += 1
        accumulatorBits += 8
      }
      output[outputIndex] = UInt32(accumulator & mask)
      accumulator >>= UInt64(bits)
      accumulatorBits -= bits
      outputIndex += 1
    }
    return output
  }

  private func matrixMultiply(
    _ matrix: Span<UInt32>,
    vector: Span<UInt32>,
    into output: inout Coefficients
  ) {
    precondition(matrix.count == k * l * degree)
    precondition(vector.count == l * degree)
    precondition(output.count == k * degree)
    // Unsafe boundary invariants:
    // - validated matrix, vector, and output counts cover every kernel offset;
    // - inputs are immutable and output has one exclusive mutable borrow;
    // - all pointers remain inside these synchronous nested closures;
    // - the pointer kernel performs aligned-type, unaligned-value SIMD loads and
    //   never stores outside the initialized output allocation.
    matrix.withUnsafeBufferPointer { matrixBuffer in
      vector.withUnsafeBufferPointer { vectorBuffer in
        output.withUnsafeMutableBufferPointer { outputBuffer in
          matrixMultiply(
            matrixBuffer.baseAddress.unsafelyUnwrapped,
            vector: vectorBuffer.baseAddress.unsafelyUnwrapped,
            into: outputBuffer.baseAddress.unsafelyUnwrapped
          )
        }
      }
    }
  }

  private func matrixMultiply(
    _ matrix: UnsafePointer<UInt32>,
    vector: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>
  ) {
    output.update(repeating: 0, count: k * degree)
    var row = 0
    while row < k {
      var column = 0
      while column < l {
        let matrixBase = (row * l + column) * degree
        let vectorBase = column * degree
        let outputBase = row * degree
        var coefficient = 0
        while coefficient + 4 <= degree {
          let matrixValues = loadSIMD4(
            matrix.advanced(by: matrixBase + coefficient)
          )
          let vectorValues = loadSIMD4(
            vector.advanced(by: vectorBase + coefficient)
          )
          let accumulated = loadSIMD4(
            output.advanced(by: outputBase + coefficient)
          )
          let product = reduceMontgomery(
            matrixValues,
            multipliedBy: vectorValues
          )
          storeSIMD4(
            reduceOnce(accumulated &+ product),
            to: output.advanced(by: outputBase + coefficient)
          )
          coefficient += 4
        }
        column += 1
      }
      row += 1
    }
  }

  private func vectorMultiplyScalar(
    _ vector: Span<UInt32>,
    scalar: Span<UInt32>,
    into output: inout Coefficients,
    polynomialCount: Int
  ) {
    precondition(vector.count == polynomialCount * degree)
    precondition(scalar.count == degree)
    precondition(output.count == vector.count)
    var polynomial = 0
    while polynomial < polynomialCount {
      let base = polynomial * degree
      var coefficient = 0
      while coefficient < degree {
        output[base + coefficient] = reduceMontgomery(
          UInt64(vector[base + coefficient]) * UInt64(scalar[coefficient])
        )
        coefficient += 1
      }
      polynomial += 1
    }
  }

  private func vectorMultiplyScalar(
    _ vector: UnsafePointer<UInt32>,
    scalar: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>,
    polynomialCount: Int
  ) {
    var polynomial = 0
    while polynomial < polynomialCount {
      let base = polynomial * degree
      var coefficient = 0
      while coefficient + 4 <= degree {
        let vectorValues = loadSIMD4(vector.advanced(by: base + coefficient))
        let scalarValues = loadSIMD4(scalar.advanced(by: coefficient))
        storeSIMD4(
          reduceMontgomery(vectorValues, multipliedBy: scalarValues),
          to: output.advanced(by: base + coefficient)
        )
        coefficient += 4
      }
      polynomial += 1
    }
  }

  private func addVector(
    _ rhs: Coefficients,
    into output: inout Coefficients
  ) {
    precondition(output.count == rhs.count)
    // The output is updated in place so no COW copy of the six-polynomial
    // accumulator is created. Both borrows are bounded and synchronous.
    let coefficientCount = output.count
    rhs.withUnsafeBufferPointer { rhsBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        addVectors(
          outputBuffer.baseAddress.unsafelyUnwrapped,
          rhsBuffer.baseAddress.unsafelyUnwrapped,
          into: outputBuffer.baseAddress.unsafelyUnwrapped,
          count: coefficientCount
        )
      }
    }
  }

  private func addVectors(
    _ lhs: UnsafePointer<UInt32>,
    _ rhs: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    var index = 0
    while index + 4 <= count {
      let lhsValues = loadSIMD4(lhs.advanced(by: index))
      let rhsValues = loadSIMD4(rhs.advanced(by: index))
      storeSIMD4(
        reduceOnce(lhsValues &+ rhsValues),
        to: output.advanced(by: index)
      )
      index += 4
    }
    while index < count {
      output[index] = reduceOnce(lhs[index] + rhs[index])
      index += 1
    }
  }

  private func subtractVector(
    _ rhs: Coefficients,
    from output: inout Coefficients
  ) {
    precondition(rhs.count == output.count)
    rhs.withUnsafeBufferPointer { rhsBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        let outputPointer = outputBuffer.baseAddress.unsafelyUnwrapped
        subtractVectors(
          outputPointer,
          rhsBuffer.baseAddress.unsafelyUnwrapped,
          into: outputPointer,
          count: outputBuffer.count
        )
      }
    }
  }

  private func subtractVectors(
    _ lhs: UnsafePointer<UInt32>,
    _ rhs: UnsafePointer<UInt32>,
    into output: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    var index = 0
    while index < count {
      output[index] = modSubtract(lhs[index], rhs[index])
      index += 1
    }
  }

  private func maximumModPrime(_ coefficients: Coefficients) -> UInt32 {
    var maximum: UInt32 = 0
    var index = 0
    while index < coefficients.count {
      let value = coefficients[index]
      let difference = value &- halfPrime &- 1
      let mask = UInt32.zero &- (difference >> 31)
      let absolute = (mask & value) | (~mask & (prime &- value))
      maximum = constantTimeMaximum(maximum, absolute)
      index += 1
    }
    return maximum
  }

  private func maximumModPrime(
    _ coefficients: UnsafePointer<UInt32>,
    count: Int
  ) -> UInt32 {
    var maximum: UInt32 = 0
    var index = 0
    while index < count {
      let value = coefficients[index]
      let difference = value &- halfPrime &- 1
      let mask = UInt32.zero &- (difference >> 31)
      let absolute = (mask & value) | (~mask & (prime &- value))
      maximum = constantTimeMaximum(maximum, absolute)
      index += 1
    }
    return maximum
  }

  private func maximumSigned(_ coefficients: Coefficients) -> UInt32 {
    var maximum: UInt32 = 0
    var index = 0
    while index < coefficients.count {
      let value = coefficients[index]
      let signMask = UInt32.zero &- (value >> 31)
      let absolute = (signMask & (0 &- value)) | (~signMask & value)
      maximum = constantTimeMaximum(maximum, absolute)
      index += 1
    }
    return maximum
  }

  private func maximumSigned(
    _ coefficients: UnsafePointer<UInt32>,
    count: Int
  ) -> UInt32 {
    var maximum: UInt32 = 0
    var index = 0
    while index < count {
      let value = coefficients[index]
      let signMask = UInt32.zero &- (value >> 31)
      let absolute = (signMask & (0 &- value)) | (~signMask & value)
      maximum = constantTimeMaximum(maximum, absolute)
      index += 1
    }
    return maximum
  }

  private func countOnes(_ coefficients: Coefficients) -> Int {
    var count = 0
    var index = 0
    while index < coefficients.count {
      count += Int(coefficients[index])
      index += 1
    }
    return count
  }

  private func countOnes(
    _ coefficients: UnsafePointer<UInt32>,
    count coefficientCount: Int
  ) -> Int {
    var count = 0
    var index = 0
    while index < coefficientCount {
      count += Int(coefficients[index])
      index += 1
    }
    return count
  }

  private func nttVector(
    _ vector: inout Coefficients,
    polynomialCount: Int
  ) {
    precondition(vector.count >= polynomialCount * degree)
    // One exclusive borrow covers the full vector. This avoids repeating COW
    // uniqueness checks at every polynomial while all pointer offsets remain
    // bounded by the validated contiguous coefficient count.
    vector.withUnsafeMutableBufferPointer { buffer in
      nttVector(
        buffer.baseAddress.unsafelyUnwrapped,
        polynomialCount: polynomialCount
      )
    }
  }

  private func nttVector(
    _ vector: UnsafeMutablePointer<UInt32>,
    polynomialCount: Int
  ) {
    var polynomial = 0
    while polynomial < polynomialCount {
      nttPolynomial(vector.advanced(by: polynomial * degree))
      polynomial += 1
    }
  }

  private func inverseNTTVector(
    _ vector: inout Coefficients,
    polynomialCount: Int
  ) {
    precondition(vector.count >= polynomialCount * degree)
    // The ownership, range, and lifetime contract matches nttVector. A single
    // scoped pointer borrow covers every polynomial and never escapes.
    vector.withUnsafeMutableBufferPointer { buffer in
      inverseNTTVector(
        buffer.baseAddress.unsafelyUnwrapped,
        polynomialCount: polynomialCount
      )
    }
  }

  private func inverseNTTVector(
    _ vector: UnsafeMutablePointer<UInt32>,
    polynomialCount: Int
  ) {
    var polynomial = 0
    while polynomial < polynomialCount {
      inverseNTTPolynomial(vector.advanced(by: polynomial * degree))
      polynomial += 1
    }
  }

  private func nttPolynomial(
    _ coefficients: inout Coefficients,
    base: Int
  ) {
    precondition(base >= 0 && base <= coefficients.count - degree)
    // Unsafe boundary invariants:
    // - coefficients uniquely owns degree initialized UInt32 values at base.
    // - the typed pointer preserves UInt32 alignment and binding.
    // - every stage accesses only indices 0..<degree.
    // - the pointer is scoped to this nonescaping borrow and never crosses a
    //   Sendable boundary.
    coefficients.withUnsafeMutableBufferPointer { buffer in
      let polynomial = buffer.baseAddress!.advanced(by: base)
      nttPolynomial(polynomial)
    }
  }

  @inline(__always)
  private func nttPolynomial(
    _ polynomial: UnsafeMutablePointer<UInt32>
  ) {
    roots.withUnsafeBufferPointer { roots in
      let rootTable = roots.baseAddress.unsafelyUnwrapped
      nttStage(polynomial, rootTable: rootTable, step: 1, offset: 128)
      nttStage(polynomial, rootTable: rootTable, step: 2, offset: 64)
      nttStage(polynomial, rootTable: rootTable, step: 4, offset: 32)
      nttStage(polynomial, rootTable: rootTable, step: 8, offset: 16)
      nttStage(polynomial, rootTable: rootTable, step: 16, offset: 8)
      nttStage(polynomial, rootTable: rootTable, step: 32, offset: 4)
      nttStage(polynomial, rootTable: rootTable, step: 64, offset: 2)
      nttStage(polynomial, rootTable: rootTable, step: 128, offset: 1)
    }
    // Eight lazy butterfly stages bound every coefficient below 9q. Reduce the
    // complete polynomial once at the domain boundary so consumers retain the
    // canonical [0, q) contract without paying two reductions per stage.
    var index = 0
    while index + 4 <= degree {
      var values = loadSIMD4(polynomial.advanced(by: index))
      values = conditionalSubtract(values, modulus: 8 * prime)
      values = conditionalSubtract(values, modulus: 4 * prime)
      values = conditionalSubtract(values, modulus: 2 * prime)
      values = conditionalSubtract(values, modulus: prime)
      storeSIMD4(values, to: polynomial.advanced(by: index))
      index += 4
    }
  }

  private func inverseNTTPolynomial(
    _ coefficients: inout Coefficients,
    base: Int
  ) {
    precondition(base >= 0 && base <= coefficients.count - degree)
    // The ownership, binding, range, and lifetime invariants match
    // nttPolynomial. All values are initialized before and after every stage.
    coefficients.withUnsafeMutableBufferPointer { buffer in
      let polynomial = buffer.baseAddress!.advanced(by: base)
      inverseNTTPolynomial(polynomial)
    }
  }

  @inline(__always)
  private func inverseNTTPolynomial(
    _ polynomial: UnsafeMutablePointer<UInt32>
  ) {
    roots.withUnsafeBufferPointer { roots in
      let rootTable = roots.baseAddress.unsafelyUnwrapped
      inverseNTTStage(polynomial, rootTable: rootTable, step: 128, offset: 1)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 64, offset: 2)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 32, offset: 4)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 16, offset: 8)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 8, offset: 16)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 4, offset: 32)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 2, offset: 64)
      inverseNTTStage(polynomial, rootTable: rootTable, step: 1, offset: 128)
    }
    var index = 0
    while index + 4 <= degree {
      storeSIMD4(
        reduceMontgomery(
          loadSIMD4(polynomial.advanced(by: index)),
          multipliedBy: inverseDegreeDoubleMontgomery
        ),
        to: polynomial.advanced(by: index)
      )
      index += 4
    }
  }

  @inline(__always)
  private func nttStage(
    _ coefficients: UnsafeMutablePointer<UInt32>,
    rootTable: UnsafePointer<UInt32>,
    step: Int,
    offset: Int
  ) {
    if offset == 2 {
      var group = 0
      var start = 0
      while group < step {
        let values = loadSIMD4(coefficients.advanced(by: start))
        let even = lowHalf(values)
        let odd = reduceMontgomery(
          highHalf(values),
          multipliedBy: SIMD2<UInt32>(repeating: rootTable[step + group])
        )
        storeSIMD4(
          combineHalves(
            low: even &+ odd,
            high: SIMD2<UInt32>(repeating: prime) &+ even &- odd
          ),
          to: coefficients.advanced(by: start)
        )
        start += 4
        group += 1
      }
      return
    }
    if offset == 1 {
      var group = 0
      var start = 0
      while group < step {
        let values = loadSIMD4(coefficients.advanced(by: start))
        let even = SIMD2(values[0], values[2])
        let oddInput = SIMD2(values[1], values[3])
        let rootValues = SIMD2(rootTable[step + group], rootTable[step + group + 1])
        let odd = reduceMontgomery(oddInput, multipliedBy: rootValues)
        let evenOutput = even &+ odd
        let oddOutput = SIMD2<UInt32>(repeating: prime) &+ even &- odd
        storeSIMD4(
          SIMD4(evenOutput[0], oddOutput[0], evenOutput[1], oddOutput[1]),
          to: coefficients.advanced(by: start)
        )
        start += 4
        group += 2
      }
      return
    }
    var group = 0
    var start = 0
    while group < step {
      let root = rootTable[step + group]
      let end = start + offset
      var index = start
      while index + 4 <= end {
        let even = loadSIMD4(coefficients.advanced(by: index))
        let oddInput = loadSIMD4(coefficients.advanced(by: index + offset))
        let odd = reduceMontgomery(oddInput, multipliedBy: root)
        storeSIMD4(
          odd &+ even,
          to: coefficients.advanced(by: index)
        )
        storeSIMD4(
          SIMD4<UInt32>(repeating: prime) &+ even &- odd,
          to: coefficients.advanced(by: index + offset)
        )
        index += 4
      }
      while index < end {
        let even = coefficients[index]
        let odd = reduceMontgomery(
          UInt64(root) * UInt64(coefficients[index + offset])
        )
        coefficients[index] = odd + even
        coefficients[index + offset] = prime + even - odd
        index += 1
      }
      start += 2 * offset
      group += 1
    }
  }

  @inline(__always)
  private func inverseNTTStage(
    _ coefficients: UnsafeMutablePointer<UInt32>,
    rootTable: UnsafePointer<UInt32>,
    step: Int,
    offset: Int
  ) {
    if offset == 1 {
      var group = 0
      var start = 0
      while group < step {
        let values = loadSIMD4(coefficients.advanced(by: start))
        let even = SIMD2(values[0], values[2])
        let odd = SIMD2(values[1], values[3])
        let firstRoot = prime - rootTable[step + (step - 1 - group)]
        let secondRoot = prime - rootTable[step + (step - 2 - group)]
        let rootValues = SIMD2(firstRoot, secondRoot)
        let evenOutput = reduceOnce(even &+ odd)
        let difference = SIMD2<UInt32>(repeating: prime) &+ even &- odd
        let oddOutput = reduceMontgomery(
          difference,
          multipliedBy: rootValues
        )
        storeSIMD4(
          SIMD4(evenOutput[0], oddOutput[0], evenOutput[1], oddOutput[1]),
          to: coefficients.advanced(by: start)
        )
        start += 4
        group += 2
      }
      return
    }
    if offset == 2 {
      var group = 0
      var start = 0
      while group < step {
        let values = loadSIMD4(coefficients.advanced(by: start))
        let even = lowHalf(values)
        let odd = highHalf(values)
        let root = prime - rootTable[step + (step - 1 - group)]
        let low = reduceOnce(even &+ odd)
        let high = reduceMontgomery(
          SIMD2<UInt32>(repeating: prime) &+ even &- odd,
          multipliedBy: SIMD2<UInt32>(repeating: root)
        )
        storeSIMD4(
          combineHalves(low: low, high: high),
          to: coefficients.advanced(by: start)
        )
        start += 4
        group += 1
      }
      return
    }
    var group = 0
    var start = 0
    while group < step {
      let root = prime - rootTable[step + (step - 1 - group)]
      let end = start + offset
      var index = start
      while index + 4 <= end {
        let even = loadSIMD4(coefficients.advanced(by: index))
        let odd = loadSIMD4(coefficients.advanced(by: index + offset))
        storeSIMD4(
          reduceOnce(odd &+ even),
          to: coefficients.advanced(by: index)
        )
        let difference = SIMD4<UInt32>(repeating: prime) &+ even &- odd
        storeSIMD4(
          reduceMontgomery(difference, multipliedBy: root),
          to: coefficients.advanced(by: index + offset)
        )
        index += 4
      }
      while index < end {
        let even = coefficients[index]
        let odd = coefficients[index + offset]
        coefficients[index] = reduceOnce(odd + even)
        coefficients[index + offset] = reduceMontgomery(
          UInt64(root) * UInt64(prime + even - odd)
        )
        index += 1
      }
      start += 2 * offset
      group += 1
    }
  }

  @inline(__always)
  private func loadSIMD4(
    _ pointer: UnsafePointer<UInt32>
  ) -> SIMD4<UInt32> {
    UnsafeRawPointer(pointer).loadUnaligned(as: SIMD4<UInt32>.self)
  }

  @inline(__always)
  private func storeSIMD4(
    _ value: SIMD4<UInt32>,
    to pointer: UnsafeMutablePointer<UInt32>
  ) {
    pointer[0] = value[0]
    pointer[1] = value[1]
    pointer[2] = value[2]
    pointer[3] = value[3]
  }

  @inline(__always)
  private func reduceMontgomery(
    _ values: SIMD4<UInt32>,
    multipliedBy multiplier: UInt32
  ) -> SIMD4<UInt32> {
    let factors = SIMD4<UInt32>(repeating: multiplier)
    return reduceMontgomery(values, multipliedBy: factors)
  }

  @inline(__always)
  private func reduceMontgomery(
    _ lhs: SIMD4<UInt32>,
    multipliedBy rhs: SIMD4<UInt32>
  ) -> SIMD4<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      let lowProducts = vmull_u32(vget_low_u32(lhs), vget_low_u32(rhs))
      let highProducts = vmull_high_u32(lhs, rhs)
      return vcombine_u32(
        reduceMontgomery(lowProducts),
        reduceMontgomery(highProducts)
      )
    #else
      let lowProducts =
        SIMD2<UInt64>(truncatingIfNeeded: lhs.lowHalf)
        &* SIMD2<UInt64>(truncatingIfNeeded: rhs.lowHalf)
      let highProducts =
        SIMD2<UInt64>(truncatingIfNeeded: lhs.highHalf)
        &* SIMD2<UInt64>(truncatingIfNeeded: rhs.highHalf)
      var result = SIMD4<UInt32>()
      result.lowHalf = reduceMontgomery(lowProducts)
      result.highHalf = reduceMontgomery(highProducts)
      return result
    #endif
  }

  @inline(__always)
  private func lowHalf(_ value: SIMD4<UInt32>) -> SIMD2<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vget_low_u32(value)
    #else
      return value.lowHalf
    #endif
  }

  @inline(__always)
  private func highHalf(_ value: SIMD4<UInt32>) -> SIMD2<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vget_high_u32(value)
    #else
      return value.highHalf
    #endif
  }

  @inline(__always)
  private func combineHalves(
    low: SIMD2<UInt32>,
    high: SIMD2<UInt32>
  ) -> SIMD4<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vcombine_u32(low, high)
    #else
      var result = SIMD4<UInt32>()
      result.lowHalf = low
      result.highHalf = high
      return result
    #endif
  }

  @inline(__always)
  private func reduceMontgomery(
    _ lhs: SIMD2<UInt32>,
    multipliedBy rhs: SIMD2<UInt32>
  ) -> SIMD2<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return reduceMontgomery(vmull_u32(lhs, rhs))
    #else
      return reduceMontgomery(
        SIMD2<UInt64>(truncatingIfNeeded: lhs)
          &* SIMD2<UInt64>(truncatingIfNeeded: rhs)
      )
    #endif
  }

  @inline(__always)
  private func reduceMontgomery(
    _ values: SIMD2<UInt64>
  ) -> SIMD2<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      let lowWords = vmovn_u64(values)
      let montgomeryMultiplier = vmul_u32(
        lowWords,
        SIMD2<UInt32>(repeating: primeNegInverse)
      )
      let sum = vmlal_u32(
        values,
        montgomeryMultiplier,
        SIMD2<UInt32>(repeating: prime)
      )
      let reduced = vmovn_u64(
        sum &>> SIMD2<UInt64>(repeating: 32)
      )
    #else
      let lowWordMask = SIMD2<UInt64>(repeating: 0xFFFF_FFFF)
      let montgomeryMultiplier =
        (values & lowWordMask)
        &* SIMD2<UInt64>(repeating: UInt64(primeNegInverse))
        & lowWordMask
      let sum =
        values &+ montgomeryMultiplier
        &* SIMD2<UInt64>(repeating: UInt64(prime))
      let reduced = SIMD2<UInt32>(
        truncatingIfNeeded: sum &>> SIMD2<UInt64>(repeating: 32)
      )
    #endif
    return reduceOnce(reduced)
  }

  @inline(__always)
  private func reduceOnce(_ values: SIMD4<UInt32>) -> SIMD4<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      // Every caller bounds each lane below 2q. When a lane is below q, the
      // subtraction wraps to a larger unsigned value; otherwise it produces
      // the canonical residue. AArch64 lowers this to SUB + UMIN.
      return vminq_u32(
        values,
        values &- SIMD4<UInt32>(repeating: prime)
      )
    #else
    let subtracted = values &- SIMD4<UInt32>(repeating: prime)
    let mask =
      SIMD4<UInt32>(repeating: 0)
      &- (subtracted &>> SIMD4<UInt32>(repeating: 31))
    return (mask & values) | (~mask & subtracted)
    #endif
  }

  @inline(__always)
  private func conditionalSubtract(
    _ values: SIMD4<UInt32>,
    modulus: UInt32
  ) -> SIMD4<UInt32> {
    let subtracted = values &- SIMD4<UInt32>(repeating: modulus)
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vminq_u32(values, subtracted)
    #else
      let mask =
        SIMD4<UInt32>(repeating: 0)
        &- (subtracted &>> SIMD4<UInt32>(repeating: 31))
      return (mask & values) | (~mask & subtracted)
    #endif
  }

  @inline(__always)
  private func reduceOnce(_ values: SIMD2<UInt32>) -> SIMD2<UInt32> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vmin_u32(
        values,
        values &- SIMD2<UInt32>(repeating: prime)
      )
    #else
    let subtracted = values &- SIMD2<UInt32>(repeating: prime)
    let mask =
      SIMD2<UInt32>(repeating: 0)
      &- (subtracted &>> SIMD2<UInt32>(repeating: 31))
    return (mask & values) | (~mask & subtracted)
    #endif
  }

  @inline(__always)
  private func modSubtract(
    _ lhs: SIMD4<UInt32>,
    _ rhs: SIMD4<UInt32>
  ) -> SIMD4<UInt32> {
    let result = lhs &- rhs
    #if os(macOS) && arch(arm64) && canImport(simd)
      // Inputs are canonical. Underflow makes result the larger unsigned
      // candidate, so UMIN selects result + q only for the wrapped lanes.
      return vminq_u32(
        result,
        result &+ SIMD4<UInt32>(repeating: prime)
      )
    #else
    let mask =
      SIMD4<UInt32>(repeating: 0)
      &- (result &>> SIMD4<UInt32>(repeating: 31))
    return (mask & (result &+ SIMD4<UInt32>(repeating: prime)))
      | (~mask & result)
    #endif
  }

  @inline(__always)
  private func modSubtract(
    _ lhs: SIMD2<UInt32>,
    _ rhs: SIMD2<UInt32>
  ) -> SIMD2<UInt32> {
    let result = lhs &- rhs
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vmin_u32(
        result,
        result &+ SIMD2<UInt32>(repeating: prime)
      )
    #else
    let mask =
      SIMD2<UInt32>(repeating: 0)
      &- (result &>> SIMD2<UInt32>(repeating: 31))
    return (mask & (result &+ SIMD2<UInt32>(repeating: prime)))
      | (~mask & result)
    #endif
  }

  private func cancelInverseNTTScale(_ coefficients: inout Coefficients) {
    var index = 0
    while index < coefficients.count {
      coefficients[index] = reduceMontgomery(UInt64(coefficients[index]))
      index += 1
    }
  }

  @inline(__always)
  private func reduceOnce(_ value: UInt32) -> UInt32 {
    let subtracted = value &- prime
    let mask = UInt32.zero &- (subtracted >> 31)
    return (mask & value) | (~mask & subtracted)
  }

  @inline(__always)
  private func modSubtract(_ lhs: UInt32, _ rhs: UInt32) -> UInt32 {
    let result = lhs &- rhs
    let mask = UInt32.zero &- (result >> 31)
    return (mask & (result &+ prime)) | (~mask & result)
  }

  @inline(__always)
  private func reduceMontgomery(_ value: UInt64) -> UInt32 {
    let multiplier = UInt32(truncatingIfNeeded: value) &* primeNegInverse
    let sum = value + UInt64(multiplier) * UInt64(prime)
    return reduceOnce(UInt32(truncatingIfNeeded: sum >> 32))
  }

  @inline(__always)
  private func constantTimeLessThan(_ lhs: UInt32, _ rhs: UInt32) -> UInt32 {
    UInt32(truncatingIfNeeded: (UInt64(lhs) &- UInt64(rhs)) >> 63)
  }

  @inline(__always)
  private func constantTimeMaximum(_ lhs: UInt32, _ rhs: UInt32) -> UInt32 {
    let mask = UInt32.zero &- constantTimeLessThan(lhs, rhs)
    return (mask & rhs) | (~mask & lhs)
  }

  private func shake256(
    outputByteCount: Int,
    absorbing input: Span<UInt8>
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try shake256(outputByteCount: outputByteCount) { sponge throws(MLDSAError) in
      try absorb(input, into: &sponge)
    }
  }

  private func shake256(
    outputByteCount: Int,
    _ absorbBody: (inout KeccakCore) throws(MLDSAError) -> Void
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    var sponge = KeccakCore(rateByteCount: 136, domainSeparator: 0x1F)
    do {
      try absorbBody(&sponge)
    } catch {
      sponge.erase()
      throw error
    }
    var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
    var destination = output.mutableSpan
    sponge.squeeze(into: &destination)
    sponge.erase()
    return output
  }

  private func absorb(
    _ input: Span<UInt8>,
    into sponge: inout KeccakCore
  ) throws(MLDSAError) {
    do {
      try sponge.update(input)
    } catch {
      throw .inputTooLong
    }
  }

  private func absorbByte(
    _ byte: UInt8,
    into sponge: inout KeccakCore
  ) throws(MLDSAError) {
    do {
      try sponge.update(byte: byte)
    } catch {
      throw .inputTooLong
    }
  }

  private func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  private func copy(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(source.count)
    append(source, to: &result)
    return result
  }

  @inline(__always)
  private func copyBytes(
    _ source: Span<UInt8>,
    to destination: UnsafeMutablePointer<UInt8>,
    at destinationOffset: Int
  ) {
    var index = 0
    while index < source.count {
      destination[destinationOffset + index] = source[index]
      index += 1
    }
  }

  private func copyPolynomial(
    _ source: Coefficients,
    sourceBase: Int,
    into destination: inout Coefficients,
    destinationBase: Int
  ) {
    var index = 0
    while index < degree {
      destination[destinationBase + index] = source[sourceBase + index]
      index += 1
    }
  }

  @inline(__always)
  private func copyCoefficients(
    from source: UnsafePointer<UInt32>,
    to destination: UnsafeMutablePointer<UInt32>,
    count: Int
  ) {
    destination.update(from: source, count: count)
  }

  private func coefficients(
    copying source: UnsafePointer<UInt32>,
    count: Int
  ) -> Coefficients {
    var result = Coefficients(repeating: 0, count: count)
    result.withUnsafeMutableBufferPointer { destination in
      destination.baseAddress.unsafelyUnwrapped.update(from: source, count: count)
    }
    return result
  }

  private func secretBytes(
    copying source: Span<UInt8>
  ) throws(MLDSAError) -> SecretBytes {
    do {
      return try SecretBytes(copying: source)
    } catch let error {
      throw .secretMemory(error)
    }
  }

  func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(baseAddress),
        byteCount: buffer.count
      )
    }
  }

  private func wipe(_ coefficients: inout Coefficients) {
    coefficients.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.eraseUInt32Words(
        baseAddress,
        wordCount: buffer.count
      )
    }
  }
}
