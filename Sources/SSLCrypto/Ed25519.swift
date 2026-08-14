import SSLCore

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

    let publicPoint = publicKey.decodedPoint
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

    let verificationPoint = EdwardsPoint.doubleScalarMultiplyBase(
      baseScalar: scalarBytes,
      subtracting: publicPoint,
      scalar: challenge.span
    )
    let leftCleared = verificationPoint.double().double().double()
    let rightCleared = rPoint.double().double().double()
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

  static func reduceScalarForTesting(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    Scalar.reduce(bytes)
  }

  static func multiplyScalarsForTesting(
    _ lhs: Span<UInt8>,
    _ rhs: Span<UInt8>
  ) -> ContiguousArray<UInt8> {
    var left = ContiguousArray<UInt8>()
    left.reserveCapacity(lhs.count)
    var index = 0
    while index < lhs.count {
      left.append(lhs[index])
      index += 1
    }
    return Scalar.multiplyMod(left, rhs)
  }

  static func scalarMultiplyBaseForTesting(_ scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
    EdwardsPoint.scalarMultiplyBase(scalar).encoded
  }

  static func scalarMultiplyGenericBaseForTesting(_ scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
    EdwardsPoint.base.scalarMultiply(scalar).encoded
  }

  static func scalarMultiplyPublicBaseForTesting(_ scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
    EdwardsPoint.base.scalarMultiplyPublic(scalar).encoded
  }

  static func doubleScalarMultiplyBaseForTesting(
    _ baseScalar: Span<UInt8>,
    subtracting pointScalar: Span<UInt8>
  ) -> ContiguousArray<UInt8> {
    EdwardsPoint.doubleScalarMultiplyBase(
      baseScalar: baseScalar,
      subtracting: EdwardsPoint.base,
      scalar: pointScalar
    ).encoded
  }

  static func referenceDoubleScalarMultiplyBaseForTesting(
    _ baseScalar: Span<UInt8>,
    subtracting pointScalar: Span<UInt8>
  ) -> ContiguousArray<UInt8> {
    EdwardsPoint.scalarMultiplyBase(baseScalar)
      .add(EdwardsPoint.base.scalarMultiply(pointScalar).negated())
      .encoded
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
    let publicKey = EdwardsPoint.scalarMultiplyBase(scalar).encoded
    return try sign(message: message, expanded: expanded, publicKey: publicKey.span)
  }

  /// Signs with a public key already derived from this seed.
  ///
  /// This SPI exists for value-oriented facades that retain the matching public
  /// key alongside the seed. The caller must guarantee that `publicKey` belongs
  /// to this private seed; a mismatch produces an invalid signature.
  @_spi(PureSwiftCrypto)
  public borrowing func sign(
    message: Span<UInt8>,
    precomputedPublicKey publicKey: Span<UInt8>
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    guard publicKey.count == Ed25519.publicKeyByteCount else {
      throw .invalidLength(expected: Ed25519.publicKeyByteCount, actual: publicKey.count)
    }
    var expanded = try Self.expand(seed: seed)
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    defer { Self.wipe(&expanded) }
    return try sign(message: message, expanded: expanded, publicKey: publicKey)
  }

  private borrowing func sign(
    message: Span<UInt8>,
    expanded: borrowing ContiguousArray<UInt8>,
    publicKey: Span<UInt8>
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    let scalar = expanded.span.extracting(0..<32)
    let prefix = expanded.span.extracting(32..<64)
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
    Self.append(&challengeInput, publicKey)
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
  private static let modulus = Value(
    word0: 0x5812_631a_5cf5_d3ed,
    word1: 0x14de_f9de_a2f7_9cd6,
    word2: 0,
    word3: 0x1000_0000_0000_0000
  )

  static func isCanonical(_ bytes: Span<UInt8>) -> Bool {
    guard bytes.count == 32 else { return false }
    var value = Value(bytes)
    return !value.subtractIfAtLeast(modulus)
  }

  static func reduce(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    // The hash is secret while signing. Fixed four-word long division performs
    // one shift and one masked subtraction per input bit. The memory access
    // pattern and control flow are independent of the scalar value, and no
    // per-bit heap allocation is performed.
    var remainder = Value.zero
    var bit = bytes.count * 8 - 1
    while bit >= 0 {
      let inputBit = UInt64((bytes[bit >> 3] >> UInt8(bit & 7)) & 1)
      remainder.shiftLeft(adding: inputBit)
      _ = remainder.subtractIfAtLeast(modulus)
      bit -= 1
    }
    let result = remainder.encoded
    remainder.wipe()
    return result
  }

  static func addMod(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var left = Value(lhs.span)
    var right = Value(rhs.span)
    var sum = left.adding(right)
    _ = sum.subtractIfAtLeast(modulus)
    let result = sum.encoded
    left.wipe()
    right.wipe()
    sum.wipe()
    return result
  }

  static func multiplyMod(
    _ lhs: ContiguousArray<UInt8>,
    _ rhs: Span<UInt8>
  ) -> ContiguousArray<UInt8> {
    var result = Value.zero
    var addend = Value(lhs.span)
    var bit = 0
    while bit < 256 {
      var sum = result.adding(addend)
      _ = sum.subtractIfAtLeast(modulus)
      let selected = UInt64((rhs[bit >> 3] >> UInt8(bit & 7)) & 1)
      result.select(sum, when: selected)
      sum.wipe()
      var doubled = addend.adding(addend)
      _ = doubled.subtractIfAtLeast(modulus)
      addend.wipe()
      addend = doubled
      bit += 1
    }
    let encoded = result.encoded
    result.wipe()
    addend.wipe()
    return encoded
  }

  private struct Value {
    var word0: UInt64
    var word1: UInt64
    var word2: UInt64
    var word3: UInt64

    static let zero = Self(word0: 0, word1: 0, word2: 0, word3: 0)

    init(word0: UInt64, word1: UInt64, word2: UInt64, word3: UInt64) {
      self.word0 = word0
      self.word1 = word1
      self.word2 = word2
      self.word3 = word3
    }

    init(_ bytes: Span<UInt8>) {
      precondition(bytes.count >= 32)
      word0 = Self.loadWord(bytes, offset: 0)
      word1 = Self.loadWord(bytes, offset: 8)
      word2 = Self.loadWord(bytes, offset: 16)
      word3 = Self.loadWord(bytes, offset: 24)
    }

    mutating func shiftLeft(adding bit: UInt64) {
      let carry0 = word0 >> 63
      let carry1 = word1 >> 63
      let carry2 = word2 >> 63
      word0 = (word0 << 1) | bit
      word1 = (word1 << 1) | carry0
      word2 = (word2 << 1) | carry1
      word3 = (word3 << 1) | carry2
    }

    func adding(_ other: Self) -> Self {
      let (sum0, overflow0) = word0.addingReportingOverflow(other.word0)
      let (partial1, overflow1A) = word1.addingReportingOverflow(other.word1)
      let (sum1, overflow1B) = partial1.addingReportingOverflow(overflow0 ? 1 : 0)
      let (partial2, overflow2A) = word2.addingReportingOverflow(other.word2)
      let (sum2, overflow2B) = partial2.addingReportingOverflow(
        (overflow1A || overflow1B) ? 1 : 0
      )
      let (partial3, overflow3A) = word3.addingReportingOverflow(other.word3)
      let (sum3, overflow3B) = partial3.addingReportingOverflow(
        (overflow2A || overflow2B) ? 1 : 0
      )
      precondition(!overflow3A && !overflow3B)
      return Self(word0: sum0, word1: sum1, word2: sum2, word3: sum3)
    }

    /// Subtracts `other` with a mask if `self >= other`.
    /// - Returns: `true` exactly when subtraction was applied.
    @discardableResult
    mutating func subtractIfAtLeast(_ other: Self) -> Bool {
      let (difference0, borrow0) = word0.subtractingReportingOverflow(other.word0)
      let (partial1, borrow1A) = word1.subtractingReportingOverflow(other.word1)
      let (difference1, borrow1B) = partial1.subtractingReportingOverflow(borrow0 ? 1 : 0)
      let borrow1 = borrow1A || borrow1B
      let (partial2, borrow2A) = word2.subtractingReportingOverflow(other.word2)
      let (difference2, borrow2B) = partial2.subtractingReportingOverflow(borrow1 ? 1 : 0)
      let borrow2 = borrow2A || borrow2B
      let (partial3, borrow3A) = word3.subtractingReportingOverflow(other.word3)
      let (difference3, borrow3B) = partial3.subtractingReportingOverflow(borrow2 ? 1 : 0)
      let borrow = borrow3A || borrow3B
      let apply = UInt64(borrow ? 0 : 1)
      let mask = UInt64(0) &- apply
      word0 = (word0 & ~mask) | (difference0 & mask)
      word1 = (word1 & ~mask) | (difference1 & mask)
      word2 = (word2 & ~mask) | (difference2 & mask)
      word3 = (word3 & ~mask) | (difference3 & mask)
      return !borrow
    }

    mutating func select(_ other: Self, when selection: UInt64) {
      let mask = UInt64(0) &- selection
      word0 = (word0 & ~mask) | (other.word0 & mask)
      word1 = (word1 & ~mask) | (other.word1 & mask)
      word2 = (word2 & ~mask) | (other.word2 & mask)
      word3 = (word3 & ~mask) | (other.word3 & mask)
    }

    var encoded: ContiguousArray<UInt8> {
      var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
      Self.storeWord(word0, into: &result, offset: 0)
      Self.storeWord(word1, into: &result, offset: 8)
      Self.storeWord(word2, into: &result, offset: 16)
      Self.storeWord(word3, into: &result, offset: 24)
      return result
    }

    mutating func wipe() {
      // The raw pointer borrows this initialized fixed-width value only for
      // the synchronous erase call and cannot escape or alias another owner.
      withUnsafeMutableBytes(of: &self) { rawBytes in
        guard let baseAddress = rawBytes.baseAddress else { return }
        SecureWipe.erase(baseAddress, byteCount: rawBytes.count)
      }
    }

    private static func loadWord(_ bytes: Span<UInt8>, offset: Int) -> UInt64 {
      var result: UInt64 = 0
      var index = 0
      while index < 8 {
        result |= UInt64(bytes[offset + index]) << UInt64(index * 8)
        index += 1
      }
      return result
    }

    private static func storeWord(
      _ word: UInt64,
      into bytes: inout ContiguousArray<UInt8>,
      offset: Int
    ) {
      var index = 0
      while index < 8 {
        bytes[offset + index] = UInt8(truncatingIfNeeded: word >> UInt64(index * 8))
        index += 1
      }
    }
  }
}

struct EdwardsPoint: Sendable {
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

  @inline(__always)
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

  @inline(__always)
  func double() -> EdwardsPoint {
    let a = x.squared()
    let b = y.squared()
    let c = z.squared().multiplied(bySmall: 2)
    let d = -a
    let e = (x + y).squared() - a - b
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

  /// Multiplies by a public scalar using a radix-16 lookup window.
  ///
  /// Verification scalars are hashes of public transcript data, so branches
  /// and table selection may depend on their digits. Secret scalar operations
  /// continue to use `scalarMultiply` or the fixed-base constant-time table.
  func scalarMultiplyPublic(_ scalar: Span<UInt8>) -> EdwardsPoint {
    precondition(scalar.count == 32)
    let window = EdwardsPublicWindow(base: self)
    var result = EdwardsPoint.identity
    var nibbleIndex = 63
    while nibbleIndex >= 0 {
      result = result.double().double().double().double()
      let byte = scalar[nibbleIndex >> 1]
      let digit = nibbleIndex & 1 == 0 ? byte & 0x0F : byte >> 4
      if digit != 0 {
        result = result.add(window.point(for: digit))
      }
      nibbleIndex -= 1
    }
    return result
  }

  /// Computes `[baseScalar]B - [scalar]point` in one public-data bit walk.
  static func doubleScalarMultiplyBase(
    baseScalar: Span<UInt8>,
    subtracting point: EdwardsPoint,
    scalar: Span<UInt8>
  ) -> EdwardsPoint {
    precondition(baseScalar.count == 32 && scalar.count == 32)
    let subtractedPoint = point.negated()
    var result = EdwardsPoint.identity
    var bit = 255
    while bit >= 0 {
      result = result.double()
      let byteIndex = bit >> 3
      let bitOffset = UInt8(bit & 7)
      if ((baseScalar[byteIndex] >> bitOffset) & 1) != 0 {
        result = result.add(EdwardsPoint.base)
      }
      if ((scalar[byteIndex] >> bitOffset) & 1) != 0 {
        result = result.add(subtractedPoint)
      }
      bit -= 1
    }
    return result
  }

  @inline(__always)
  func negated() -> EdwardsPoint {
    EdwardsPoint(x: -x, y: y, z: z, t: -t)
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
    let point = X25519FixedBase.scalarMultiplyEdwards(scalar: scalar)
    return EdwardsPoint(x: point.x, y: point.y, z: point.z, t: point.t)
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

private struct EdwardsPublicWindow {
  let point1: EdwardsPoint
  let point2: EdwardsPoint
  let point3: EdwardsPoint
  let point4: EdwardsPoint
  let point5: EdwardsPoint
  let point6: EdwardsPoint
  let point7: EdwardsPoint
  let point8: EdwardsPoint
  let point9: EdwardsPoint
  let point10: EdwardsPoint
  let point11: EdwardsPoint
  let point12: EdwardsPoint
  let point13: EdwardsPoint
  let point14: EdwardsPoint
  let point15: EdwardsPoint

  init(base: EdwardsPoint) {
    point1 = base
    point2 = base.double()
    point3 = point2.add(base)
    point4 = point3.add(base)
    point5 = point4.add(base)
    point6 = point5.add(base)
    point7 = point6.add(base)
    point8 = point7.add(base)
    point9 = point8.add(base)
    point10 = point9.add(base)
    point11 = point10.add(base)
    point12 = point11.add(base)
    point13 = point12.add(base)
    point14 = point13.add(base)
    point15 = point14.add(base)
  }

  @inline(__always)
  func point(for digit: UInt8) -> EdwardsPoint {
    switch digit {
    case 1: point1
    case 2: point2
    case 3: point3
    case 4: point4
    case 5: point5
    case 6: point6
    case 7: point7
    case 8: point8
    case 9: point9
    case 10: point10
    case 11: point11
    case 12: point12
    case 13: point13
    case 14: point14
    case 15: point15
    default: EdwardsPoint.identity
    }
  }
}
