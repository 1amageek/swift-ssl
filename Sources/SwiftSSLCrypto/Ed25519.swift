import SwiftSSLCore

/// Ed25519 signature verification using extended Edwards coordinates.
public enum Ed25519: DigitalSignature {
  public typealias PublicKey = Ed25519PublicKey
  public typealias PrivateKey = Ed25519PrivateKey

  public static let publicKeyByteCount = 32
  public static let signatureByteCount = 64

  public static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    using publicKey: borrowing Ed25519PublicKey
  ) throws(CryptoInputError) -> Bool {
    guard signature.count == Self.signatureByteCount else {
      throw .invalidLength(expected: Self.signatureByteCount, actual: signature.count)
    }

    let publicPoint = try EdwardsPoint.decode(publicKey.span)
    let rPoint = try EdwardsPoint.decode(signature.extracting(0..<32))
    let scalarBytes = signature.extracting(32..<64)
    guard Scalar.isCanonical(scalarBytes) else {
      throw .nonCanonicalEncoding
    }

    var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
    let digestByteCount = digest.count
    do {
      try digest.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
        let baseAddress = buffer.baseAddress!
        var context = SHA512.makeContext()
        try context.update(signature.extracting(0..<32))
        try context.update(publicKey.span)
        try context.update(message)
        var output = MutableSpan(_unsafeStart: baseAddress, count: digestByteCount)
        try context.finalize(into: &output)
      }
    } catch {
      throw .invalidSignature
    }
    let challenge = Scalar.reduce(digest.span)
    Self.wipe(&digest)

    let left = EdwardsPoint.scalarMultiplyBase(scalarBytes)
    let right = rPoint.add(publicPoint.scalarMultiply(challenge.span))
    let leftCleared = left.double().double().double()
    let rightCleared = right.double().double().double()
    return leftCleared.isEqual(to: rightCleared)
  }

  public static func sign(
    message: Span<UInt8>,
    using privateKey: borrowing Ed25519PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    try privateKey.sign(message: message)
  }

  static func validatePublicKey(_ bytes: Span<UInt8>) throws(CryptoInputError) {
    _ = try EdwardsPoint.decode(bytes)
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }
}

/// Ed25519 private seed owner implementing deterministic RFC 8032 signing.
public struct Ed25519PrivateKey: ~Copyable, Sendable {
  public static let seedByteCount = 32

  private let seed: SecretBytes

  public init(seed: Span<UInt8>) throws(CryptoInputError) {
    guard seed.count == Self.seedByteCount else {
      throw .invalidLength(expected: Self.seedByteCount, actual: seed.count)
    }
    do {
      self.seed = try SecretBytes(copying: seed)
    } catch {
      throw .invalidLength(expected: Self.seedByteCount, actual: seed.count)
    }
  }

  public borrowing func publicKey() throws(CryptoInputError) -> ContiguousArray<UInt8> {
    var expanded = try Self.expand(seed: seed)
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    defer { Self.wipe(&expanded) }
    return EdwardsPoint.scalarMultiplyBase(
      expanded.span.extracting(0..<32)
    ).encoded
  }

  public borrowing func sign(message: Span<UInt8>) throws(CryptoInputError) -> ContiguousArray<
    UInt8
  > {
    var expanded = try Self.expand(seed: seed)
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    defer { Self.wipe(&expanded) }

    let scalar = expanded.span.extracting(0..<32)
    let prefix = expanded.span.extracting(32..<64)
    let publicKey = EdwardsPoint.scalarMultiplyBase(scalar).encoded
    var nonceInput = ContiguousArray<UInt8>()
    nonceInput.reserveCapacity(prefix.count + message.count)
    Self.append(&nonceInput, prefix)
    Self.append(&nonceInput, message)
    defer { Self.wipe(&nonceInput) }
    var nonceDigest = try Self.hash(nonceInput.span)
    defer { Self.wipe(&nonceDigest) }
    var nonce = Scalar.reduce(nonceDigest.span)
    defer { Self.wipe(&nonce) }
    let encodedR = EdwardsPoint.scalarMultiplyBase(nonce.span).encoded

    var challengeInput = ContiguousArray<UInt8>()
    challengeInput.reserveCapacity(encodedR.count + publicKey.count + message.count)
    challengeInput.append(contentsOf: encodedR)
    challengeInput.append(contentsOf: publicKey)
    Self.append(&challengeInput, message)
    var challengeDigest = try Self.hash(challengeInput.span)
    defer { Self.wipe(&challengeDigest) }
    let challenge = Scalar.reduce(challengeDigest.span)
    let response = Scalar.addMod(
      nonce,
      Scalar.multiplyMod(challenge, scalar)
    )

    var signature = ContiguousArray<UInt8>()
    signature.reserveCapacity(Ed25519.signatureByteCount)
    signature.append(contentsOf: encodedR)
    signature.append(contentsOf: response)
    return signature
  }

  private static func expand(seed: borrowing SecretBytes) throws(CryptoInputError)
    -> ContiguousArray<UInt8>
  {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
    do {
      try seed.withBorrowedBytes { bytes throws(CryptoInputError) in
        var destination = output.mutableSpan
        try SHA512.hash(bytes, into: &destination)
      }
    } catch {
      throw .invalidSignature
    }
    return output
  }

  private static func hash(_ input: Span<UInt8>) throws(CryptoInputError) -> ContiguousArray<UInt8>
  {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
    var destination = output.mutableSpan
    try SHA512.hash(input, into: &destination)
    return output
  }

  private static func append(_ target: inout ContiguousArray<UInt8>, _ source: Span<UInt8>) {
    var index = 0
    while index < source.count {
      target.append(source[index])
      index += 1
    }
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }
}

private struct Scalar {
  private static let modulus: ContiguousArray<UInt8> = hexBytes(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
  )

  static func isCanonical(_ bytes: Span<UInt8>) -> Bool {
    var index = bytes.count - 1
    while index >= 0 {
      if bytes[index] < modulus[index] { return true }
      if bytes[index] > modulus[index] { return false }
      index -= 1
    }
    return false
  }

  static func reduce(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    // The 64-byte hash is secret while signing. Long division performs one
    // shift and one masked conditional subtraction for every input bit, so
    // control flow and memory indices do not depend on the reduced value.
    var remainder = ContiguousArray<UInt8>(repeating: 0, count: 33)
    var bit = bytes.count * 8 - 1
    while bit >= 0 {
      let inputBit = (bytes[bit >> 3] >> UInt8(bit & 7)) & 1
      var carry = inputBit
      var index = 0
      while index < remainder.count {
        let nextCarry = remainder[index] >> 7
        remainder[index] = (remainder[index] << 1) | carry
        carry = nextCarry
        index += 1
      }
      Self.subtractModulusIfPossible(&remainder)
      bit -= 1
    }
    var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var resultIndex = 0
    while resultIndex < 32 {
      result[resultIndex] = remainder[resultIndex]
      resultIndex += 1
    }
    return result
  }

  static func addMod(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>(repeating: 0, count: 33)
    var carry: UInt16 = 0
    var index = 0
    while index < 32 {
      let value = UInt16(lhs[index]) + UInt16(rhs[index]) + carry
      result[index] = UInt8(truncatingIfNeeded: value)
      carry = value >> 8
      index += 1
    }
    result[32] = UInt8(truncatingIfNeeded: carry)
    Self.subtractModulusIfPossible(&result)
    result.removeLast()
    return result
  }

  static func multiplyMod(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: Span<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var addend = lhs
    var bit = 0
    while bit < 256 {
      let sum = Self.addMod(result, addend)
      let selected = (rhs[bit >> 3] >> UInt8(bit & 7)) & 1
      Self.select(&result, sum, when: selected)
      addend = Self.addMod(addend, addend)
      bit += 1
    }
    return result
  }

  private static func subtractModulusIfPossible(
    _ value: inout ContiguousArray<UInt8>
  ) {
    var difference = ContiguousArray<UInt8>(repeating: 0, count: value.count)
    var borrow: UInt16 = 0
    var index = 0
    while index < value.count {
      let subtrahend = UInt16(index < modulus.count ? modulus[index] : 0) + borrow
      let minuend = UInt16(value[index])
      difference[index] = UInt8(truncatingIfNeeded: minuend &- subtrahend)
      borrow = UInt16(minuend < subtrahend ? 1 : 0)
      index += 1
    }
    let useDifference = UInt8(truncatingIfNeeded: UInt16(1) &- borrow)
    Self.select(&value, difference, when: useDifference)
  }

  private static func select(
    _ whenZero: inout ContiguousArray<UInt8>,
    _ whenOne: ContiguousArray<UInt8>,
    when select: UInt8
  ) {
    let mask = UInt8(0) &- select
    var index = 0
    while index < whenZero.count {
      whenZero[index] = (whenZero[index] & ~mask) | (whenOne[index] & mask)
      index += 1
    }
  }

  private static func hexBytes(_ string: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(string.utf8.count / 2)
    var high: UInt8 = 0
    var haveHigh = false
    for byte in string.utf8 {
      let value: UInt8
      switch byte {
      case 0x30...0x39: value = byte - 0x30
      case 0x61...0x66: value = byte - 0x61 + 10
      default: value = 0
      }
      if haveHigh {
        result.append((high << 4) | value)
        haveHigh = false
      } else {
        high = value
        haveHigh = true
      }
    }
    return result
  }
}

private struct EdwardsPoint {
  let x: Field25519
  let y: Field25519
  let z: Field25519
  let t: Field25519

  static let identity = EdwardsPoint(
    x: Field25519(constant: 0),
    y: Field25519(one: true),
    z: Field25519(one: true),
    t: Field25519(constant: 0)
  )

  static let base = EdwardsPoint(
    x: Field25519(
      bytes: hexBytes("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921").span),
    y: Field25519(
      bytes: hexBytes("5866666666666666666666666666666666666666666666666666666666666666").span),
    z: Field25519(one: true),
    t: Field25519(
      bytes: hexBytes("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921").span)
      * Field25519(
        bytes: hexBytes("5866666666666666666666666666666666666666666666666666666666666666").span)
  )

  func add(_ other: EdwardsPoint) -> EdwardsPoint {
    let a = (y - x) * (other.y - other.x)
    let b = (y + x) * (other.y + other.x)
    let c = t * Field25519.edwardsTwoD * other.t
    let d = z * Field25519(constant: 2) * other.z
    let e = b - a
    let f = d - c
    let g = d + c
    let h = b + a
    return EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)
  }

  func double() -> EdwardsPoint {
    let a = x * x
    let b = y * y
    let c = Field25519(constant: 2) * z * z
    let d = -a
    let e = (x + y) * (x + y) - a - b
    let g = d + b
    let f = g - c
    let h = d - b
    return EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)
  }

  func scalarMultiply(_ scalar: Span<UInt8>) -> EdwardsPoint {
    // Secret scalar bits never select a control-flow edge. Every iteration
    // computes both the addition and doubling and selects field limbs with
    // a mask. All storage is owned by local values and no borrow escapes.
    var result = EdwardsPoint.identity
    var addend = self
    var bit = 0
    while bit < 256 {
      let sum = result.add(addend)
      let selected = UInt64((scalar[bit >> 3] >> UInt8(bit & 7)) & 1)
      result = EdwardsPoint.selecting(result, sum, select: selected)
      addend = addend.double()
      bit += 1
    }
    return result
  }

  private static func selecting(
    _ whenZero: EdwardsPoint,
    _ whenOne: EdwardsPoint,
    select: UInt64
  ) -> EdwardsPoint {
    EdwardsPoint(
      x: Field25519.selecting(whenZero.x, whenOne.x, select: select),
      y: Field25519.selecting(whenZero.y, whenOne.y, select: select),
      z: Field25519.selecting(whenZero.z, whenOne.z, select: select),
      t: Field25519.selecting(whenZero.t, whenOne.t, select: select)
    )
  }

  static func scalarMultiplyBase(_ scalar: Span<UInt8>) -> EdwardsPoint {
    EdwardsPoint.base.scalarMultiply(scalar)
  }

  static func decode(_ bytes: Span<UInt8>) throws(CryptoInputError) -> EdwardsPoint {
    var yBytes = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var index = 0
    while index < 32 {
      yBytes[index] = bytes[index]
      index += 1
    }
    let sign = (yBytes[31] >> 7) & 1
    yBytes[31] &= 0x7F
    let y = Field25519(bytes: yBytes.span)
    guard y.bytes == yBytes else {
      throw .nonCanonicalEncoding
    }
    let ySquared = y * y
    let u = ySquared - Field25519(constant: 1)
    let v = Field25519.edwardsD * ySquared + Field25519(constant: 1)
    var x = Self.sqrtRatio(u: u, v: v)
    guard (x * x * v).bytes == u.bytes else {
      throw .invalidSignature
    }
    if x.isNegative != (sign == 1) {
      x = -x
    }
    if x.isZero && sign == 1 {
      throw .invalidSignature
    }
    return EdwardsPoint(x: x, y: y, z: Field25519(one: true), t: x * y)
  }

  func isEqual(to other: EdwardsPoint) -> Bool {
    let xLeft = x * other.z
    let xRight = other.x * z
    let yLeft = y * other.z
    let yRight = other.y * z
    return xLeft.bytes == xRight.bytes && yLeft.bytes == yRight.bytes
  }

  var encoded: ContiguousArray<UInt8> {
    let inverseZ = z.inverted()
    let affineX = x * inverseZ
    let affineY = y * inverseZ
    var result = affineY.bytes
    if affineX.isNegative {
      result[31] |= 0x80
    }
    return result
  }

  private static func sqrtRatio(u: Field25519, v: Field25519) -> Field25519 {
    let v2 = v * v
    let v3 = v2 * v
    let v7 = v3 * v3 * v
    let uv7 = u * v7
    let exponent = uv7
    var result = Field25519(one: true)
    var bit = 251
    while bit >= 0 {
      result = result * result
      if bit >= 2 || bit == 0 {
        result = result * exponent
      }
      bit -= 1
    }
    var candidate = u * v3 * result
    let candidateCheck = candidate * candidate * v
    let negativeU = -u
    if candidateCheck.bytes == negativeU.bytes {
      candidate = candidate * Field25519.edwardsSqrtM1
    }
    return candidate
  }

  private static func hexBytes(_ string: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(string.utf8.count / 2)
    var high: UInt8 = 0
    var haveHigh = false
    for byte in string.utf8 {
      let value: UInt8
      switch byte {
      case 0x30...0x39: value = byte - 0x30
      case 0x61...0x66: value = byte - 0x61 + 10
      default: value = 0
      }
      if haveHigh {
        result.append((high << 4) | value)
        haveHigh = false
      } else {
        high = value
        haveHigh = true
      }
    }
    return result
  }
}
