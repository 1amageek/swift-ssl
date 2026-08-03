struct MLDSAParameterSet: Sendable {
  let k: Int
  let l: Int
  let eta: UInt32
  let gamma1: UInt32
  let gamma2Divisor: UInt32
  let beta: UInt32
  let omega: Int
  let tau: Int
  let challengeByteCount: Int
  let publicKeyByteCount: Int
  let privateKeyByteCount: Int
  let signatureByteCount: Int

  var shortCoefficientBitCount: Int { eta == 4 ? 4 : 3 }
  var maskCoefficientBitCount: Int { gamma1 == 1 << 19 ? 20 : 18 }
  var maskPolynomialByteCount: Int { maskCoefficientBitCount * 256 / 8 }
  var highBitsCoefficientBitCount: Int { gamma2Divisor == 32 ? 4 : 6 }
  var privateS1Offset: Int { 128 }
  var privateS2Offset: Int {
    privateS1Offset + l * shortCoefficientBitCount * 256 / 8
  }
  var privateT0Offset: Int {
    privateS2Offset + k * shortCoefficientBitCount * 256 / 8
  }
  var signatureZOffset: Int { challengeByteCount }
  var signatureHintOffset: Int {
    signatureZOffset + l * maskPolynomialByteCount
  }

  static let mlDSA44 = Self(
    k: 4,
    l: 4,
    eta: 2,
    gamma1: 1 << 17,
    gamma2Divisor: 88,
    beta: 78,
    omega: 80,
    tau: 39,
    challengeByteCount: 32,
    publicKeyByteCount: 1_312,
    privateKeyByteCount: 2_560,
    signatureByteCount: 2_420
  )

  static let mlDSA65 = Self(
    k: 6,
    l: 5,
    eta: 4,
    gamma1: 1 << 19,
    gamma2Divisor: 32,
    beta: 196,
    omega: 55,
    tau: 49,
    challengeByteCount: 48,
    publicKeyByteCount: 1_952,
    privateKeyByteCount: 4_032,
    signatureByteCount: 3_309
  )

  static let mlDSA87 = Self(
    k: 8,
    l: 7,
    eta: 2,
    gamma1: 1 << 19,
    gamma2Divisor: 32,
    beta: 120,
    omega: 75,
    tau: 60,
    challengeByteCount: 64,
    publicKeyByteCount: 2_592,
    privateKeyByteCount: 4_896,
    signatureByteCount: 4_627
  )
}
