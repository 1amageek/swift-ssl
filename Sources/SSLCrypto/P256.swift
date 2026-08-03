import SSLCore

/// P-256 ECDSA over a caller-provided message digest.
///
/// The public key, digest, and signature are public verification inputs, so
/// this implementation does not carry a secret-dependent timing contract.
/// The raw signature format is fixed-width `r || s`; DER decoding belongs to
/// the X.509/ASN.1 layer.
public enum P256ECDSA: DigestSignatureVerifier {
  public typealias PublicKey = P256PublicKey

  public static let signatureByteCount = 64

  /// Creates a deterministic raw ECDSA signature encoded as fixed-width
  /// `r || s` using RFC 6979 HMAC-SHA-256 nonce generation.
  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing P256PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    guard messageHash.count >= SHA256.digestByteCount else {
      throw .invalidLength(
        expected: SHA256.digestByteCount,
        actual: messageHash.count
      )
    }

    var digest = P256Scalar(
      bytes: messageHash.extracting(0..<SHA256.digestByteCount)
    ).reduced
    defer { digest.wipe() }
    return try privateKey.withBorrowedBytes { privateBytes throws(CryptoInputError) in
      var privateScalar = P256Scalar(bytes: privateBytes)
      defer { privateScalar.wipe() }
      var generator = try P256RFC6979State(
        privateScalar: privateBytes,
        messageScalar: digest
      )
      var nonce = try generator.nextScalar()
      defer { nonce.wipe() }
      var encodedNonce = nonce.encoded
      let noncePoint = P256Point.scalarMultiplyGeneratorSecret(
        scalar: encodedNonce.span
      )
      Self.wipe(&encodedNonce)
      guard let affine = noncePoint.affine() else {
        throw .invalidSignature
      }

      let r = P256Scalar(words: affine.x.canonicalWords).reduced
      guard !r.isZero else { throw .invalidSignature }
      var inverse = nonce.inverted()
      defer { inverse.wipe() }
      let s = inverse * (digest + (r * privateScalar))
      guard !s.isZero else { throw .invalidSignature }

      var signature = ContiguousArray<UInt8>()
      signature.reserveCapacity(Self.signatureByteCount)
      signature.append(contentsOf: r.encoded)
      signature.append(contentsOf: s.encoded)
      return signature
    }
  }

  /// Verifies a raw ECDSA signature encoded as fixed-width `r || s`.
  ///
  /// The digest is interpreted as a big-endian integer and truncated to the
  /// curve order width, as specified by SEC 1. The caller is responsible for
  /// selecting the digest algorithm named by the surrounding protocol.
  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing P256PublicKey
  ) throws(CryptoInputError) -> Bool {
    guard signature.count == Self.signatureByteCount else {
      throw .invalidLength(expected: Self.signatureByteCount, actual: signature.count)
    }
    guard messageHash.count >= 32 else {
      throw .invalidLength(expected: 32, actual: messageHash.count)
    }

    let r = P256Scalar(bytes: signature.extracting(0..<32))
    let s = P256Scalar(bytes: signature.extracting(32..<64))
    guard !r.isZero, !s.isZero, r < .order, s < .order else {
      throw .nonCanonicalEncoding
    }

    let digest = P256Scalar(bytes: messageHash.extracting(0..<32)).reduced
    let inverse = s.inverted()
    let u1 = digest * inverse
    let u2 = r * inverse

    let point: P256Point
    do {
      point = try publicKey.withBorrowedPoint { publicPoint throws(CryptoInputError) in
        let first = P256Point.scalarMultiply(P256Point.generator, scalar: u1.encoded.span)
        let second = P256Point.scalarMultiply(publicPoint, scalar: u2.encoded.span)
        return first.adding(second)
      }
    } catch {
      throw .invalidPeerKey
    }
    guard let affine = point.affine() else { return false }
    return P256Scalar(words: affine.x.canonicalWords).reduced == r
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    // Unsafe boundary invariants:
    // - bytes uniquely owns initialized UInt8 storage for this synchronous scope.
    // - The raw mutable pointer is borrowed only by SecureWipe and never escapes.
    // - UInt8 has stride and alignment one; no binding or overlapping alias exists.
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(baseAddress),
        byteCount: buffer.count
      )
    }
  }
}

/// Noncopyable RFC 6979 state for deterministic P-256 signing.
private struct P256RFC6979State: ~Copyable {
  private static let candidateCount = 4
  private var key: SecretBytes
  private var value: SecretBytes

  init(
    privateScalar: Span<UInt8>,
    messageScalar: P256Scalar
  ) throws(CryptoInputError) {
    var key = Self.makeFilledSecret(0)
    var value = Self.makeFilledSecret(1)
    key = try Self.hmacInitialization(
      key: key,
      value: value,
      marker: 0,
      privateScalar: privateScalar,
      messageScalar: messageScalar
    )
    value = try Self.hmacValue(message: value, key: key)
    key = try Self.hmacInitialization(
      key: key,
      value: value,
      marker: 1,
      privateScalar: privateScalar,
      messageScalar: messageScalar
    )
    value = try Self.hmacValue(message: value, key: key)
    self.key = key
    self.value = value
  }

  mutating func nextScalar() throws(CryptoInputError) -> P256Scalar {
    var selected = P256Scalar.zero
    var foundMask: UInt32 = 0
    var attempt = 0
    while attempt < Self.candidateCount {
      let candidate = try advanceCandidate()
      let candidateMask = candidate.validPrivateScalarMask
      let selectionMask = candidateMask & ~foundMask
      selected = P256Scalar.select(
        mask: selectionMask,
        candidate,
        selected
      )
      foundMask |= candidateMask
      attempt += 1
    }
    guard foundMask == UInt32.max else {
      selected.wipe()
      throw .invalidSignature
    }
    return selected
  }

  private mutating func advanceCandidate()
    throws(CryptoInputError) -> P256Scalar
  {
    value = try Self.hmacValue(message: value, key: key)
    let candidate = value.withBorrowedBytes { P256Scalar(bytes: $0) }

    let rejectedKey = try Self.hmacRejection(key: key, value: value)
    let rejectedValue = try Self.hmacValue(
      message: value,
      key: rejectedKey
    )
    key = rejectedKey
    value = rejectedValue
    return candidate
  }

  private static func hmacInitialization(
    key: borrowing SecretBytes,
    value: borrowing SecretBytes,
    marker: UInt8,
    privateScalar: Span<UInt8>,
    messageScalar: P256Scalar
  ) throws(CryptoInputError) -> SecretBytes {
    var context = try key.withBorrowedBytes { bytes throws(CryptoInputError) in
      try HMACSHA256.makeContext(authenticatingWith: bytes)
    }
    try value.withBorrowedBytes { bytes throws(CryptoInputError) in
      try context.update(bytes)
    }
    let markerBytes: ContiguousArray<UInt8> = [marker]
    try context.update(markerBytes.span)
    try context.update(privateScalar)
    let encodedMessage = messageScalar.encoded
    try context.update(encodedMessage.span)
    return try Self.finalize(context: context)
  }

  private static func hmacRejection(
    key: borrowing SecretBytes,
    value: borrowing SecretBytes
  ) throws(CryptoInputError) -> SecretBytes {
    var context = try key.withBorrowedBytes { bytes throws(CryptoInputError) in
      try HMACSHA256.makeContext(authenticatingWith: bytes)
    }
    try value.withBorrowedBytes { bytes throws(CryptoInputError) in
      try context.update(bytes)
    }
    let marker: ContiguousArray<UInt8> = [0]
    try context.update(marker.span)
    return try Self.finalize(context: context)
  }

  private static func hmacValue(
    message: borrowing SecretBytes,
    key: borrowing SecretBytes
  ) throws(CryptoInputError) -> SecretBytes {
    var context = try key.withBorrowedBytes { bytes throws(CryptoInputError) in
      try HMACSHA256.makeContext(authenticatingWith: bytes)
    }
    try message.withBorrowedBytes { bytes throws(CryptoInputError) in
      try context.update(bytes)
    }
    return try Self.finalize(context: context)
  }

  private static func finalize(
    context: consuming HMACSHA256Context
  ) throws(CryptoInputError) -> SecretBytes {
    var bytes = ContiguousArray<UInt8>(
      repeating: 0,
      count: SHA256.digestByteCount
    )
    defer { Self.wipe(&bytes) }
    var destination = bytes.mutableSpan
    try context.finalize(into: &destination)
    do {
      return try SecretBytes(copying: bytes.span)
    } catch {
      preconditionFailure("RFC 6979 state size is a compile-time constant")
    }
  }

  private static func makeFilledSecret(_ byte: UInt8) -> SecretBytes {
    SecretBytes(byteCount: Self.byteCount()) { destination in
      var index = 0
      while index < destination.count {
        destination[index] = byte
        index += 1
      }
    }
  }

  private static func byteCount() -> SecretByteCount {
    do {
      return try SecretByteCount(SHA256.digestByteCount)
    } catch {
      preconditionFailure("RFC 6979 state size is a compile-time constant")
    }
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    // Unsafe boundary invariants:
    // - bytes uniquely owns initialized UInt8 storage for this synchronous scope.
    // - The raw mutable pointer is borrowed only by SecureWipe and never escapes.
    // - UInt8 has stride and alignment one; no binding or overlapping alias exists.
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(baseAddress),
        byteCount: buffer.count
      )
    }
  }
}

public struct P256PublicKey: Sendable, Equatable {
  public static let uncompressedByteCount = 65
  private let storage: OwnedBytes
  private let point: P256Point
  private let precomputation: P256Point.SecretCombMultiplicationTable

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.uncompressedByteCount else {
      throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
    }
    guard let point = P256Point.decodeUncompressed(bytes) else {
      throw .invalidPeerKey
    }
    self.storage = OwnedBytes(copying: bytes)
    self.point = point
    self.precomputation = P256Point.SecretCombMultiplicationTable(point: point)
  }

  init(
    consumingValidatedBytes bytes: consuming ContiguousArray<UInt8>,
    point: P256Point
  ) {
    storage = OwnedBytes(consuming: bytes)
    self.point = point
    self.precomputation = P256Point.SecretCombMultiplicationTable(point: point)
  }

  public var span: Span<UInt8> {
    @_lifetime(borrow self)
    borrowing get {
      storage.span
    }
  }

  /// Shares the immutable encoded-key owner without materializing its bytes.
  var ownedBytes: OwnedBytes { storage }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }

  borrowing func withBorrowedPoint<Result: ~Copyable, Failure: Error>(
    _ body: (P256Point) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(point)
  }

  borrowing func multiplyingSecretScalar(_ scalar: Span<UInt8>) -> P256Point {
    P256Point.scalarMultiplySecretComb(precomputation, scalar: scalar)
  }

  public static func == (lhs: P256PublicKey, rhs: P256PublicKey) -> Bool {
    lhs.storage == rhs.storage
  }
}

private struct P256Scalar: Equatable, Comparable {
  static let order = P256Scalar(
    hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
  static let zero = P256Scalar(words: SIMD8<UInt32>(repeating: 0))
  static let one = P256Scalar(
    words: SIMD8<UInt32>(1, 0, 0, 0, 0, 0, 0, 0)
  )
  var words: SIMD8<UInt32>

  init(bytes: Span<UInt8>) {
    self.words = P256Words.decode(bytes)
  }

  init(hex: String) {
    self.words = P256Words.decode(hex: hex)
  }

  init(words: SIMD8<UInt32>) {
    self.words = words
  }

  var isZero: Bool {
    nonzeroMask == 0
  }

  var nonzeroMask: UInt32 {
    P256Words.nonzeroMask(words)
  }

  var validPrivateScalarMask: UInt32 {
    nonzeroMask & P256Words.lessThanMask(words, Self.order.words)
  }

  var reduced: P256Scalar {
    P256Scalar(
      words: P256Words.reduce(
        words,
        highWord: 0,
        modulo: Self.order.words
      )
    )
  }

  var encoded: ContiguousArray<UInt8> {
    P256Words.encode(words)
  }

  func inverted() -> P256Scalar {
    Self.power(self, exponent: Self.inverseExponent)
  }

  static func + (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    var result = SIMD8<UInt32>(repeating: 0)
    var carry: UInt64 = 0
    var index = 0
    while index < 8 {
      let sum = UInt64(lhs.words[index]) + UInt64(rhs.words[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    return P256Scalar(
      words: P256Words.reduce(
        result,
        highWord: carry,
        modulo: Self.order.words
      )
    )
  }

  static func - (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    var result = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let minuend = UInt64(lhs.words[index])
      let subtrahend = UInt64(rhs.words[index]) + borrow
      let difference = minuend &- subtrahend
      result[index] = UInt32(truncatingIfNeeded: difference)
      borrow = difference >> 63
      index += 1
    }
    let corrected = P256Words.add(result, Self.order.words)
    let mask = UInt32(0) &- UInt32(truncatingIfNeeded: borrow)
    return P256Scalar(
      words: P256Words.select(mask: mask, corrected, result)
    )
  }

  static func * (lhs: P256Scalar, rhs: P256Scalar) -> P256Scalar {
    // The loop count, indexes, additions, and reductions are fixed. A secret
    // multiplier bit selects with a mask after both alternatives are computed.
    var result = Self.zero
    var addend = lhs
    var bit = 0
    while bit < 256 {
      let sum = result + addend
      let selected = (rhs.words[bit >> 5] >> UInt32(bit & 31)) & 1
      let mask = UInt32(0) &- selected
      result = Self.select(mask: mask, sum, result)
      addend = addend + addend
      bit += 1
    }
    return result
  }

  private static let inverseExponent = P256Words.decode(
    hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F"
  )

  private static func power(_ value: P256Scalar, exponent: SIMD8<UInt32>) -> P256Scalar {
    var one = SIMD8<UInt32>(repeating: 0)
    one[0] = 1
    var result = P256Scalar(words: one)
    var bit = 255
    while bit >= 0 {
      result = result * result
      if ((exponent[bit >> 5] >> UInt32(bit & 31)) & 1) == 1 {
        result = result * value
      }
      bit -= 1
    }
    return result
  }

  static func < (lhs: P256Scalar, rhs: P256Scalar) -> Bool {
    P256Words.lessThanMask(lhs.words, rhs.words) == UInt32.max
  }

  static func select(
    mask: UInt32,
    _ selected: P256Scalar,
    _ alternative: P256Scalar
  ) -> P256Scalar {
    P256Scalar(
      words: P256Words.select(
        mask: mask,
        selected.words,
        alternative.words
      )
    )
  }

  mutating func wipe() {
    // Unsafe boundary invariants:
    // - words is one initialized stack-local SIMD value owned by this scalar.
    // - The raw mutable borrow is scoped to SecureWipe and never escapes.
    // - No binding, aliasing, or Sendable boundary is introduced.
    withUnsafeMutableBytes(of: &words) { bytes in
      SecureWipe.erase(
        bytes.baseAddress.unsafelyUnwrapped,
        byteCount: bytes.count
      )
    }
  }
}

struct P256Field: Equatable {
  static let modulus = SIMD8<UInt32>(
    0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0001, 0xFFFF_FFFF
  )
  private static let sqrtExponent = SIMD8<UInt32>(
    0x0000_0000, 0x0000_0000, 0x4000_0000, 0x0000_0000,
    0x0000_0000, 0x4000_0000, 0xC000_0000, 0x3FFF_FFFF
  )

  let words: SIMD4<UInt64>

  init(words: SIMD8<UInt32>) {
    self.words = P256Words.montgomeryMultiply(
      P256Words.widen(words),
      Self.montgomeryR2
    )
  }

  private init(montgomeryWords: SIMD4<UInt64>) {
    words = montgomeryWords
  }

  init(constant: UInt32) {
    var words = SIMD8<UInt32>(repeating: 0)
    words[0] = constant
    self.init(words: words)
  }

  init(hex: String) {
    self.init(words: P256Words.decode(hex: hex))
  }

  static let zero = P256Field(constant: 0)
  static let one = P256Field(constant: 1)
  static let curveB = P256Field(
    hex: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")

  var isZero: Bool {
    var value: UInt64 = 0
    var index = 0
    while index < 4 {
      value |= words[index]
      index += 1
    }
    return value == 0
  }

  var zeroMask: UInt64 {
    ~P256Words.nonzeroWideMask(words)
  }

  var canonicalWords: SIMD8<UInt32> {
    P256Words.narrow(
      P256Words.montgomeryMultiply(
        words,
        SIMD4<UInt64>(1, 0, 0, 0)
      )
    )
  }

  var isOdd: Bool { canonicalWords[0] & 1 == 1 }

  var encoded: ContiguousArray<UInt8> {
    P256Words.encode(canonicalWords)
  }

  func writeEncoded(into destination: inout MutableSpan<UInt8>) {
    precondition(destination.count == 32)
    let canonical = canonicalWords
    var word = 0
    while word < 8 {
      let offset = (7 - word) * 4
      let value = canonical[word]
      destination[offset] = UInt8(truncatingIfNeeded: value >> 24)
      destination[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
      destination[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
      destination[offset + 3] = UInt8(truncatingIfNeeded: value)
      word += 1
    }
  }

  static func select(
    mask: UInt64,
    _ selected: P256Field,
    _ alternative: P256Field
  ) -> P256Field {
    P256Field(
      montgomeryWords: P256Words.selectWide(
        mask: mask,
        selected.words,
        alternative.words
      )
    )
  }

  // ARM64 Darwin needs whole-field inlining to keep the Montgomery limbs in
  // registers. Other targets retain ordinary function boundaries so the same
  // arithmetic does not create oversized WASM stack frames.
  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static func + (lhs: P256Field, rhs: P256Field) -> P256Field {
    let sum0 = UInt128(lhs.words[0]) &+ UInt128(rhs.words[0])
    let sum1 = UInt128(lhs.words[1])
      &+ UInt128(rhs.words[1]) &+ (sum0 >> 64)
    let sum2 = UInt128(lhs.words[2])
      &+ UInt128(rhs.words[2]) &+ (sum1 >> 64)
    let sum3 = UInt128(lhs.words[3])
      &+ UInt128(rhs.words[3]) &+ (sum2 >> 64)
    return P256Field(
      montgomeryWords: P256Words.reduceP256(
        SIMD4<UInt64>(
          UInt64(truncatingIfNeeded: sum0),
          UInt64(truncatingIfNeeded: sum1),
          UInt64(truncatingIfNeeded: sum2),
          UInt64(truncatingIfNeeded: sum3)
        ),
        highWord: UInt64(truncatingIfNeeded: sum3 >> 64)
      )
    )
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static func - (lhs: P256Field, rhs: P256Field) -> P256Field {
    let difference0 = UInt128(lhs.words[0]) &- UInt128(rhs.words[0])
    let difference1 = UInt128(lhs.words[1])
      &- (UInt128(rhs.words[1]) &+ (difference0 >> 127))
    let difference2 = UInt128(lhs.words[2])
      &- (UInt128(rhs.words[2]) &+ (difference1 >> 127))
    let difference3 = UInt128(lhs.words[3])
      &- (UInt128(rhs.words[3]) &+ (difference2 >> 127))
    let mask = UInt64(0) &- UInt64(truncatingIfNeeded: difference3 >> 127)
    let correction0 = UInt128(UInt64(truncatingIfNeeded: difference0))
      &+ UInt128(0xFFFF_FFFF_FFFF_FFFF & mask)
    let correction1 = UInt128(UInt64(truncatingIfNeeded: difference1))
      &+ UInt128(0x0000_0000_FFFF_FFFF & mask) &+ (correction0 >> 64)
    let correction2 = UInt128(UInt64(truncatingIfNeeded: difference2))
      &+ (correction1 >> 64)
    let correction3 = UInt128(UInt64(truncatingIfNeeded: difference3))
      &+ UInt128(0xFFFF_FFFF_0000_0001 & mask) &+ (correction2 >> 64)
    return P256Field(
      montgomeryWords: SIMD4<UInt64>(
        UInt64(truncatingIfNeeded: correction0),
        UInt64(truncatingIfNeeded: correction1),
        UInt64(truncatingIfNeeded: correction2),
        UInt64(truncatingIfNeeded: correction3)
      )
    )
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static prefix func - (value: P256Field) -> P256Field {
    P256Field(montgomeryWords: SIMD4<UInt64>(repeating: 0)) - value
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static func * (lhs: P256Field, rhs: P256Field) -> P256Field {
    // The P-256 least-significant 64-bit modulus limb is 2^64 - 1,
    // therefore the Montgomery factor -p[0]^-1 is exactly one. One fixed
    // four-limb reduction preserves the internal Montgomery representation.
    return P256Field(
      montgomeryWords: P256Words.montgomeryMultiply(
        lhs.words,
        rhs.words
      )
    )
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func squared() -> P256Field {
    P256Field(montgomeryWords: P256Words.montgomerySquare(words))
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func doubled() -> P256Field { self + self }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func tripled() -> P256Field { doubled() + self }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func quadrupled() -> P256Field { doubled().doubled() }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func octupled() -> P256Field { quadrupled().doubled() }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  func halved() -> P256Field {
    // Montgomery representation is linear, so dividing the stored residue by
    // two also divides the represented field element. For an odd residue, add
    // the odd modulus before shifting. The mask, carry chain, and memory access
    // are independent of the field value.
    let mask = UInt64(0) &- (words[0] & 1)
    let sum0 = UInt128(words[0])
      &+ UInt128(0xFFFF_FFFF_FFFF_FFFF & mask)
    let sum1 = UInt128(words[1])
      &+ UInt128(0x0000_0000_FFFF_FFFF & mask) &+ (sum0 >> 64)
    let sum2 = UInt128(words[2]) &+ (sum1 >> 64)
    let sum3 = UInt128(words[3])
      &+ UInt128(0xFFFF_FFFF_0000_0001 & mask) &+ (sum2 >> 64)
    let high = UInt64(truncatingIfNeeded: sum3 >> 64)
    let word3 = UInt64(truncatingIfNeeded: sum3)
    let word2 = UInt64(truncatingIfNeeded: sum2)
    let word1 = UInt64(truncatingIfNeeded: sum1)
    let word0 = UInt64(truncatingIfNeeded: sum0)
    return P256Field(
      montgomeryWords: SIMD4<UInt64>(
        (word0 >> 1) | (word1 << 63),
        (word1 >> 1) | (word2 << 63),
        (word2 >> 1) | (word3 << 63),
        (word3 >> 1) | (high << 63)
      )
    )
  }

  func inverted() -> P256Field {
    inverseSquared() * self
  }

  /// Returns `self^-2` using the fixed P-256 field addition chain.
  ///
  /// All loop counts are public constants. The chain performs 255 squarings
  /// and 11 multiplications without exponent-bit-dependent control flow.
  func inverseSquared() -> P256Field {
    let x2 = squared() * self
    let x3 = x2.squared() * self
    let x6 = x3.repeatedSquared(3) * x3
    let x12 = x6.repeatedSquared(6) * x6
    let x15 = x12.repeatedSquared(3) * x3
    let x30 = x15.repeatedSquared(15) * x15
    let x32 = x30.repeatedSquared(2) * x2

    var result = x32.repeatedSquared(32) * self
    result = result.repeatedSquared(128) * x32
    result = result.repeatedSquared(32) * x32
    result = result.repeatedSquared(30) * x30
    return result.repeatedSquared(2)
  }

  func squareRoot() -> P256Field? {
    let candidate = Self.power(self, exponent: Self.sqrtExponent)
    return candidate.squared() == self ? candidate : nil
  }

  private static func power(_ value: P256Field, exponent: SIMD8<UInt32>) -> P256Field {
    var result = P256Field.one
    var bit = 255
    while bit >= 0 {
      result = result.squared()
      if ((exponent[bit >> 5] >> UInt32(bit & 31)) & 1) == 1 {
        result = result * value
      }
      bit -= 1
    }
    return result
  }

  @inline(__always)
  private func repeatedSquared(_ count: Int) -> P256Field {
    var result = self
    var iteration = 0
    while iteration < count {
      result = result.squared()
      iteration += 1
    }
    return result
  }

  private static let montgomeryR2 = SIMD4<UInt64>(
    0x0000_0000_0000_0003,
    0xFFFF_FFFB_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFE,
    0x0000_0004_FFFF_FFFD
  )
}

struct P256Point {
  static let infinity = P256Point(x: .zero, y: .zero, z: .zero)
  static let generator = P256Point(
    x: P256Field(hex: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    y: P256Field(hex: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    z: .one
  )
  private static let generatorSecretTable = GeneratorMultiplicationTable()

  let x: P256Field
  let y: P256Field
  let z: P256Field

  var isInfinity: Bool { z.isZero }

  init(x: P256Field, y: P256Field, z: P256Field) {
    self.x = x
    self.y = y
    self.z = z
  }

  static func decodeUncompressed(_ bytes: Span<UInt8>) -> P256Point? {
    guard bytes.count == 65, bytes[0] == 0x04 else { return nil }
    let xWords = P256Words.decode(bytes.extracting(1..<33))
    let yWords = P256Words.decode(bytes.extracting(33..<65))
    guard P256Words.compare(xWords, P256Field.modulus) < 0,
      P256Words.compare(yWords, P256Field.modulus) < 0
    else { return nil }
    let x = P256Field(words: xWords)
    let y = P256Field(words: yWords)
    let point = P256Point(x: x, y: y, z: .one)
    return point.isOnCurve ? point : nil
  }

  var isOnCurve: Bool {
    guard !isInfinity else { return false }
    let left = y.squared()
    let right = x.squared() * x - x.tripled() + P256Field.curveB
    return left == right
  }

  var encodedUncompressed: ContiguousArray<UInt8> {
    guard let affine = affine() else { return [] }
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(65)
    bytes.append(0x04)
    bytes.append(contentsOf: affine.x.encoded)
    bytes.append(contentsOf: affine.y.encoded)
    return bytes
  }

  static func isValidSecretScalar(_ scalar: Span<UInt8>) -> Bool {
    guard scalar.count == 32 else { return false }
    let words = P256Words.decode(scalar)
    let nonzero = P256Words.nonzeroMask(words)
    let belowOrder = P256Words.lessThanMask(words, P256Scalar.order.words)
    return (nonzero & belowOrder) == UInt32.max
  }

  static func scalarMultiplySecret(
    _ point: P256Point,
    scalar: Span<UInt8>
  ) -> P256Point {
    precondition(scalar.count == 32)
    return scalarMultiplySecret(
      SecretMultiplicationTable(point: point),
      scalar: scalar
    )
  }

  static func scalarMultiplyGeneratorSecret(
    scalar: Span<UInt8>
  ) -> P256Point {
    precondition(scalar.count == 32)
    // Unsafe boundary invariants:
    // - scalarWords owns exactly 32 initialized bytes of secret-derived data.
    // - The owner remains stack-local and is wiped exactly once on every exit.
    // - Table indexes and loop bounds depend only on the public window number;
    //   every secret digit selects all thirty-two entries with arithmetic masks.
    // - The mutable raw-memory borrow is synchronous and never escapes.
    var scalarWords = P256Words.decode(scalar)
    defer {
      withUnsafeMutableBytes(of: &scalarWords) { bytes in
        SecureWipe.erase(bytes.baseAddress.unsafelyUnwrapped, byteCount: bytes.count)
      }
    }

    var window = 0
    var recoded = recodeGeneratorWindow(scalarWords, window: window)
    var selected = generatorSecretTable.selecting(
      window: window,
      digit: recoded.digit
    )
    var result = Self.select(
      mask: recoded.signMask,
      P256Point(x: selected.x, y: -selected.y, z: selected.z),
      selected
    )
    window += 1
    while window < 43 {
      recoded = recodeGeneratorWindow(scalarWords, window: window)
      selected = generatorSecretTable.selecting(
        window: window,
        digit: recoded.digit
      )
      let signed = Self.select(
        mask: recoded.signMask,
        P256Point(x: selected.x, y: -selected.y, z: selected.z),
        selected
      )
      result = result.addingWindowEntry(signed)
      window += 1
    }
    return result
  }

  static func scalarMultiplySecretComb(
    _ table: borrowing SecretCombMultiplicationTable,
    scalar: Span<UInt8>
  ) -> P256Point {
    precondition(scalar.count == 32)
    // Unsafe boundary invariants:
    // - scalarWords owns exactly 32 initialized bytes of secret-derived data.
    // - The owner remains stack-local and is wiped exactly once on every exit.
    // - Every public comb column scans all sixty-three affine entries; secret bits
    //   affect arithmetic masks only and never select an address or branch.
    // - The mutable raw-memory borrow is synchronous and never escapes.
    var scalarWords = P256Words.decode(scalar)
    defer {
      withUnsafeMutableBytes(of: &scalarWords) { bytes in
        SecureWipe.erase(bytes.baseAddress.unsafelyUnwrapped, byteCount: bytes.count)
      }
    }

    var column = 42
    var result = table.selecting(
      digit: P256Words.combDigit(scalarWords, column: column)
    )
    column -= 1
    while column >= 0 {
      result = result.doubledComplete()
      let selected = table.selecting(
        digit: P256Words.combDigit(scalarWords, column: column)
      )
      result = result.addingCombEntryComplete(selected)
      column -= 1
    }
    return result
  }

  static func scalarMultiplySecret(
    _ table: borrowing SecretMultiplicationTable,
    scalar: Span<UInt8>
  ) -> P256Point {
    precondition(scalar.count == 32)
    // Unsafe boundary invariants:
    // - scalarWords owns exactly 32 initialized bytes of secret-derived data.
    // - The owner remains stack-local and is wiped exactly once on every exit.
    // - The mutable raw-memory borrow is synchronous and its pointer never
    //   escapes this function or crosses a Sendable boundary.
    var scalarWords = P256Words.decode(scalar)
    defer {
      withUnsafeMutableBytes(of: &scalarWords) { bytes in
        SecureWipe.erase(bytes.baseAddress.unsafelyUnwrapped, byteCount: bytes.count)
      }
    }
    var result = P256Point.infinity
    var window = 64
    while window >= 0 {
      if window != 64 {
        var doubling = 0
        while doubling < 4 {
          result = result.doubledComplete()
          doubling += 1
        }
      }
      let recoded = recodeSecretWindow(scalarWords, window: window)
      let selected = table.selecting(recoded.digit)
      let signed = Self.select(
        mask: recoded.signMask,
        P256Point(x: selected.x, y: -selected.y, z: selected.z),
        selected
      )
      if window == 64 {
        result = signed
      } else {
        result = result.addingWindowEntry(signed)
      }
      window -= 1
    }
    return result
  }

  @inline(__always)
  private static func recodeSecretWindow(
    _ scalarWords: SIMD8<UInt32>,
    window: Int
  ) -> (digit: UInt64, signMask: UInt64) {
    let bits = P256Words.boothWindowBits(scalarWords, window: window)
    let signMask = UInt64(0) &- (bits >> 4)
    var digit = (UInt64(32) &- bits &- 1) & signMask
    digit |= bits & ~signMask
    digit = (digit >> 1) &+ (digit & 1)
    return (digit, signMask)
  }

  @inline(__always)
  private static func recodeGeneratorWindow(
    _ scalarWords: SIMD8<UInt32>,
    window: Int
  ) -> (digit: UInt64, signMask: UInt64) {
    let bits = P256Words.generatorBoothWindowBits(scalarWords, window: window)
    let signMask = UInt64(0) &- (bits >> 6)
    var digit = (UInt64(128) &- bits &- 1) & signMask
    digit |= bits & ~signMask
    digit = (digit >> 1) &+ (digit & 1)
    return (digit, signMask)
  }

  /// An immutable affine table for fixed-window secret scalar multiplication.
  ///
  /// The input point is public. Table construction may therefore use the
  /// variable-time point API. Lookup scans all nonzero entries with fixed
  /// control flow, and no field pointer or borrowed scalar view escapes.
  struct SecretMultiplicationTable: Sendable {
    struct AffinePoint: Sendable {
      let x: P256Field
      let y: P256Field

      init(_ point: P256Point) {
        x = point.x
        y = point.y
      }
    }

    private let p1: AffinePoint
    private let p2: AffinePoint
    private let p3: AffinePoint
    private let p4: AffinePoint
    private let p5: AffinePoint
    private let p6: AffinePoint
    private let p7: AffinePoint
    private let p8: AffinePoint

    init(point: P256Point) {
      let p1 = point
      let p2 = point.doubled()
      // The validated affine input has prime order greater than eight.
      // Starting at 2P, each next multiple is therefore a finite point distinct
      // from P, so the faster mixed-add formula has no doubling exception.
      let p3 = p2.addingDistinctAffine(point)
      let p4 = p3.addingDistinctAffine(point)
      let p5 = p4.addingDistinctAffine(point)
      let p6 = p5.addingDistinctAffine(point)
      let p7 = p6.addingDistinctAffine(point)
      let p8 = p7.addingDistinctAffine(point)

      // The input is a validated finite point whose order is prime and larger
      // than eight, so every entry is finite. One batch inversion converts
      // the immutable public table to affine form outside the ECDH hot path.
      let product1 = p1.z
      let product2 = product1 * p2.z
      let product3 = product2 * p3.z
      let product4 = product3 * p4.z
      let product5 = product4 * p5.z
      let product6 = product5 * p6.z
      let product7 = product6 * p7.z
      let product8 = product7 * p8.z

      var inverse = product8.inverted()
      let inverse8 = inverse * product7
      inverse = inverse * p8.z
      let inverse7 = inverse * product6
      inverse = inverse * p7.z
      let inverse6 = inverse * product5
      inverse = inverse * p6.z
      let inverse5 = inverse * product4
      inverse = inverse * p5.z
      let inverse4 = inverse * product3
      inverse = inverse * p4.z
      let inverse3 = inverse * product2
      inverse = inverse * p3.z
      let inverse2 = inverse * product1
      let inverse1 = inverse * p2.z

      self.p1 = AffinePoint(p1.affineAssumingFinite(zInverse: inverse1))
      self.p2 = AffinePoint(p2.affineAssumingFinite(zInverse: inverse2))
      self.p3 = AffinePoint(p3.affineAssumingFinite(zInverse: inverse3))
      self.p4 = AffinePoint(p4.affineAssumingFinite(zInverse: inverse4))
      self.p5 = AffinePoint(p5.affineAssumingFinite(zInverse: inverse5))
      self.p6 = AffinePoint(p6.affineAssumingFinite(zInverse: inverse6))
      self.p7 = AffinePoint(p7.affineAssumingFinite(zInverse: inverse7))
      self.p8 = AffinePoint(p8.affineAssumingFinite(zInverse: inverse8))
    }

    @inline(__always)
    func selecting(_ index: UInt64) -> P256Point {
      var x = P256Field.zero
      var y = P256Field.zero
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 1), p1, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 2), p2, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 3), p3, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 4), p4, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 5), p5, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 6), p6, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 7), p7, x, y)
      (x, y) = Self.select(mask: P256Words.equalWordMask(index, 8), p8, x, y)
      let nonzeroMask = ~P256Words.equalWordMask(index, 0)
      return P256Point(
        x: x,
        y: y,
        z: P256Field.select(mask: nonzeroMask, .one, .zero)
      )
    }

    @inline(__always)
    private static func select(
      mask: UInt64,
      _ point: AffinePoint,
      _ x: P256Field,
      _ y: P256Field
    ) -> (P256Field, P256Field) {
      (
        P256Field.select(mask: mask, point.x, x),
        P256Field.select(mask: mask, point.y, y)
      )
    }

    func appendAffinePoints(
      to destination: inout ContiguousArray<AffinePoint>
    ) {
      destination.append(p1)
      destination.append(p2)
      destination.append(p3)
      destination.append(p4)
      destination.append(p5)
      destination.append(p6)
      destination.append(p7)
      destination.append(p8)
    }

  }

  /// Six-way, 43-column comb precomputation for reusable public keys.
  ///
  /// Construction depends only on the public point. It performs the expensive
  /// basis doublings once, batch-normalizes all sixty-three nonzero combinations,
  /// and stores one immutable COW allocation. Each ECDH operation then uses 42
  /// doublings instead of 260 while retaining fixed control flow.
  struct SecretCombMultiplicationTable: Sendable {
    private struct AffinePoint: Sendable {
      let x: P256Field
      let y: P256Field

      init(_ point: P256Point) {
        x = point.x
        y = point.y
      }
    }

    private let entries: ContiguousArray<AffinePoint>

    init(point: P256Point) {
      var bases = ContiguousArray<P256Point>()
      bases.reserveCapacity(6)
      bases.append(point)
      var basis = point
      var basisIndex = 1
      while basisIndex < 6 {
        var doubling = 0
        while doubling < 43 {
          basis = basis.doubled()
          doubling += 1
        }
        bases.append(basis)
        basisIndex += 1
      }

      var projective = ContiguousArray<P256Point>()
      projective.reserveCapacity(63)
      var digit = 1
      while digit < 64 {
        var combination = P256Point.infinity
        var bit = 0
        while bit < 6 {
          if (digit & (1 << bit)) != 0 {
            combination = combination.adding(bases[bit])
          }
          bit += 1
        }
        projective.append(combination)
        digit += 1
      }
      entries = Self.batchAffine(projective)
    }

    @inline(__always)
    func selecting(digit: UInt64) -> P256Point {
      var x = P256Field.zero
      var y = P256Field.zero
      var index = 0
      while index < 63 {
        let entry = entries[index]
        let mask = P256Words.equalWordMask(digit, UInt64(index + 1))
        x = P256Field.select(mask: mask, entry.x, x)
        y = P256Field.select(mask: mask, entry.y, y)
        index += 1
      }
      let nonzeroMask = ~P256Words.equalWordMask(digit, 0)
      return P256Point(
        x: x,
        y: y,
        z: P256Field.select(mask: nonzeroMask, .one, .zero)
      )
    }

    private static func batchAffine(
      _ points: ContiguousArray<P256Point>
    ) -> ContiguousArray<AffinePoint> {
      precondition(points.count == 63)
      var products = ContiguousArray<P256Field>()
      products.reserveCapacity(points.count)
      var product = P256Field.one
      var index = 0
      while index < points.count {
        product = product * points[index].z
        products.append(product)
        index += 1
      }

      var inverse = product.inverted()
      var affine = ContiguousArray(
        repeating: AffinePoint(P256Point.generator),
        count: points.count
      )
      index = points.count - 1
      while index >= 0 {
        let prefix = index == 0 ? P256Field.one : products[index - 1]
        let zInverse = inverse * prefix
        affine[index] = AffinePoint(
          points[index].affineAssumingFinite(zInverse: zInverse)
        )
        inverse = inverse * points[index].z
        index -= 1
      }
      return affine
    }
  }

  /// Immutable width-six position-specific multiples of the standard generator.
  ///
  /// Construction uses only public constants and runs once under Swift's
  /// thread-safe static initialization. Secret multiplication scans exactly
  /// thirty-two affine entries for each of 43 public window positions, removing
  /// all 258 point doublings from the per-operation fixed-base path.
  private struct GeneratorMultiplicationTable: Sendable {
    private let entries: ContiguousArray<SecretMultiplicationTable.AffinePoint>

    init() {
      var entries = ContiguousArray<SecretMultiplicationTable.AffinePoint>()
      entries.reserveCapacity(43 * 32)
      var base = P256Point.generator
      var window = 0
      while window < 43 {
        Self.appendAffineMultiples(of: base, to: &entries)
        var doubling = 0
        while doubling < 6 {
          base = base.doubled()
          doubling += 1
        }
        window += 1
      }
      self.entries = entries
    }

    @inline(__always)
    func selecting(window: Int, digit: UInt64) -> P256Point {
      precondition(window >= 0 && window < 43)
      let start = window * 32
      var x = P256Field.zero
      var y = P256Field.zero
      var entryIndex = 0
      while entryIndex < 32 {
        let entry = entries[start + entryIndex]
        let mask = P256Words.equalWordMask(digit, UInt64(entryIndex + 1))
        x = P256Field.select(mask: mask, entry.x, x)
        y = P256Field.select(mask: mask, entry.y, y)
        entryIndex += 1
      }
      let nonzeroMask = ~P256Words.equalWordMask(digit, 0)
      return P256Point(
        x: x,
        y: y,
        z: P256Field.select(mask: nonzeroMask, .one, .zero)
      )
    }

    private static func appendAffineMultiples(
      of base: P256Point,
      to destination: inout ContiguousArray<SecretMultiplicationTable.AffinePoint>
    ) {
      var points = ContiguousArray<P256Point>()
      points.reserveCapacity(32)
      var point = base
      var index = 0
      while index < 32 {
        points.append(point)
        point = point.adding(base)
        index += 1
      }

      var products = ContiguousArray<P256Field>()
      products.reserveCapacity(32)
      var product = P256Field.one
      index = 0
      while index < 32 {
        product = product * points[index].z
        products.append(product)
        index += 1
      }

      var inverse = product.inverted()
      var affine = ContiguousArray(
        repeating: SecretMultiplicationTable.AffinePoint(P256Point.generator),
        count: 32
      )
      index = 31
      while index >= 0 {
        let prefix = index == 0 ? P256Field.one : products[index - 1]
        let zInverse = inverse * prefix
        affine[index] = SecretMultiplicationTable.AffinePoint(
          points[index].affineAssumingFinite(zInverse: zInverse)
        )
        inverse = inverse * points[index].z
        index -= 1
      }
      destination.append(contentsOf: affine)
    }
  }

  func writeUncompressedAssumingFinite(
    into destination: inout MutableSpan<UInt8>
  ) {
    precondition(destination.count == P256PublicKey.uncompressedByteCount)
    let affine = affineAssumingFinite()
    destination[0] = 0x04
    var x = destination._mutatingExtracting(1..<33)
    affine.x.writeEncoded(into: &x)
    var y = destination._mutatingExtracting(33..<65)
    affine.y.writeEncoded(into: &y)
  }

  func writeXCoordinateAssumingFinite(
    into destination: inout MutableSpan<UInt8>
  ) {
    precondition(destination.count == 32)
    (x * z.inverseSquared()).writeEncoded(into: &destination)
  }

  func affine() -> P256Point? {
    guard !isInfinity else { return nil }
    let inverseSquared = z.inverseSquared()
    let affineX = x * inverseSquared
    let affineY = y * z * inverseSquared.squared()
    return P256Point(x: affineX, y: affineY, z: .one)
  }

  private func affineAssumingFinite() -> P256Point {
    let inverseSquared = z.inverseSquared()
    return P256Point(
      x: x * inverseSquared,
      y: y * z * inverseSquared.squared(),
      z: .one
    )
  }

  private func affineAssumingFinite(zInverse: P256Field) -> P256Point {
    let inverseSquared = zInverse.squared()
    return P256Point(
      x: x * inverseSquared,
      y: y * zInverse * inverseSquared,
      z: .one
    )
  }

  private static func select(
    mask: UInt64,
    _ selected: P256Point,
    _ alternative: P256Point
  ) -> P256Point {
    P256Point(
      x: P256Field.select(mask: mask, selected.x, alternative.x),
      y: P256Field.select(mask: mask, selected.y, alternative.y),
      z: P256Field.select(mask: mask, selected.z, alternative.z)
    )
  }

  private func doubledComplete() -> P256Point {
    doubledComplete(zSquared: z.squared())
  }

  @inline(__always)
  private func doubledComplete(zSquared: P256Field) -> P256Point {
    // Reachable inputs are prime-order subgroup points or canonical infinity.
    // A finite subgroup point cannot have y == 0, and the formulas map the
    // canonical (0, 0, 0) infinity representation back to itself. No
    // exceptional mask selection is required after the arithmetic.
    let doubledY = y.doubled()
    let s = doubledY.squared()
    let m = ((x - zSquared) * (x + zSquared)).tripled()
    let beta = x * s
    let x3 = m.squared() - beta.doubled()
    let y3 = m * (beta - x3) - s.squared().halved()
    let z3 = (y * z).doubled()
    return P256Point(x: x3, y: y3, z: z3)
  }

  /// Adds one fixed-window table entry to the secret scalar accumulator.
  ///
  /// P-256's prime group order and the five-bit signed recoding guarantee that
  /// the accumulator and selected table entry cannot be equal in a nontrivial
  /// addition. Infinity inputs are selected with masks after the generic
  /// formula, so the equal-point doubling path is intentionally absent.
  private func addingWindowEntry(_ other: P256Point) -> P256Point {
    let generic = addingDistinctAffine(other)
    var result = generic
    result = Self.select(mask: other.z.zeroMask, self, result)
    result = Self.select(mask: z.zeroMask, other, result)
    return result
  }

  /// Adds a finite affine point known to differ from this finite point.
  ///
  /// This narrow contract is used while constructing public multiplication
  /// tables, where the caller proves all exceptional cases are absent.
  @inline(__always)
  private func addingDistinctAffine(_ other: P256Point) -> P256Point {
    let z1Squared = z.squared()
    let u2 = other.x * z1Squared
    let s2 = other.y * z * z1Squared
    let h = u2 - x
    let hSquared = h.squared()
    let hCubed = h * hSquared
    let r = s2 - y
    let v = x * hSquared
    let x3 = r.squared() - hCubed - v.doubled()
    return P256Point(
      x: x3,
      y: r * (v - x3) - y * hCubed,
      z: z * h
    )
  }

  /// Complete constant-control-flow mixed addition for comb multiplication.
  ///
  /// Unlike signed fixed-window accumulation, independent comb columns can
  /// make the accumulator equal to the selected entry. The generic result,
  /// doubling result, inverse-point infinity, and either-input infinity cases
  /// are therefore computed and selected without secret-dependent branches.
  private func addingCombEntryComplete(_ other: P256Point) -> P256Point {
    let z1Squared = z.squared()
    let u2 = other.x * z1Squared
    let s2 = other.y * z * z1Squared
    let h = u2 - x
    let hSquared = h.squared()
    let hCubed = h * hSquared
    let r = s2 - y
    let v = x * hSquared
    let x3 = r.squared() - hCubed - v.doubled()
    let generic = P256Point(
      x: x3,
      y: r * (v - x3) - y * hCubed,
      z: z * h
    )
    let hZeroMask = h.zeroMask
    let rZeroMask = r.zeroMask
    let equalMask = hZeroMask & rZeroMask
    let inverseMask = hZeroMask & ~rZeroMask
    var result = generic
    result = Self.select(
      mask: equalMask,
      doubledComplete(zSquared: z1Squared),
      result
    )
    result = Self.select(mask: inverseMask, .infinity, result)
    result = Self.select(mask: other.z.zeroMask, self, result)
    result = Self.select(mask: z.zeroMask, other, result)
    return result
  }

  func doubled() -> P256Point {
    guard !isInfinity, !y.isZero else { return .infinity }
    let zSquared = z.squared()
    let doubledY = y.doubled()
    let s = doubledY.squared()
    let m = ((x - zSquared) * (x + zSquared)).tripled()
    let beta = x * s
    let x3 = m.squared() - beta.doubled()
    let y3 = m * (beta - x3) - s.squared().halved()
    let z3 = (y * z).doubled()
    return P256Point(x: x3, y: y3, z: z3)
  }

  func adding(_ other: P256Point) -> P256Point {
    guard !isInfinity else { return other }
    guard !other.isInfinity else { return self }
    let z1Squared = z.squared()
    let z2Squared = other.z.squared()
    let u1 = x * z2Squared
    let u2 = other.x * z1Squared
    let s1 = y * other.z * z2Squared
    let s2 = other.y * z * z1Squared
    if u1 == u2 {
      return s1 == s2 ? doubled() : .infinity
    }
    let h = u2 - u1
    let i = h.doubled().squared()
    let j = h * i
    let r = (s2 - s1).doubled()
    let v = u1 * i
    let x3 = r.squared() - j - v.doubled()
    let y3 = r * (v - x3) - (s1 * j).doubled()
    let z3 = ((z + other.z).squared() - z1Squared - z2Squared) * h
    return P256Point(x: x3, y: y3, z: z3)
  }

  static func scalarMultiply(_ point: P256Point, scalar: Span<UInt8>) -> P256Point {
    var result = P256Point.infinity
    var byteIndex = 0
    while byteIndex < scalar.count {
      var bit = 7
      while bit >= 0 {
        result = result.doubled()
        if ((scalar[byteIndex] >> UInt8(bit)) & 1) == 1 {
          result = result.adding(point)
        }
        bit -= 1
      }
      byteIndex += 1
    }
    return result
  }
}

private enum P256Words {
  @inline(__always)
  static func combDigit(
    _ words: SIMD8<UInt32>,
    column: Int
  ) -> UInt64 {
    precondition(column >= 0 && column < 43)
    var digit: UInt64 = 0
    var row = 0
    while row < 6 {
      let bitIndex = column + row * 43
      if bitIndex < 256 {
        let word = bitIndex >> 5
        let shift = UInt32(bitIndex & 31)
        digit |= UInt64((words[word] >> shift) & 1) << UInt64(row)
      }
      row += 1
    }
    return digit
  }

  /// Extracts the five overlapping bits used by width-four Booth recoding.
  ///
  /// `window` is public and constrained to `0...51` by the caller's fixed
  /// loop. Every branch and memory index therefore depends only on the public
  /// window number, never on scalar contents.
  @inline(__always)
  static func boothWindowBits(
    _ words: SIMD8<UInt32>,
    window: Int
  ) -> UInt64 {
    precondition(window >= 0 && window < 65)
    if window == 0 {
      return UInt64(words[0] & 0x0F) << 1
    }
    let lowBit = window * 4 - 1
    let wordIndex = lowBit >> 5
    let shift = lowBit & 31
    let low = UInt64(words[wordIndex]) >> UInt64(shift)
    let high: UInt64
    if shift > 27 && wordIndex < 7 {
      high = UInt64(words[wordIndex + 1]) << UInt64(32 - shift)
    } else {
      high = 0
    }
    return (low | high) & 0x1F
  }

  /// Extracts the seven overlapping bits used by width-six fixed-base Booth
  /// recoding. The window number controls every branch and memory access.
  @inline(__always)
  static func generatorBoothWindowBits(
    _ words: SIMD8<UInt32>,
    window: Int
  ) -> UInt64 {
    precondition(window >= 0 && window < 43)
    if window == 0 {
      return UInt64(words[0] & 0x3F) << 1
    }
    let lowBit = window * 6 - 1
    let wordIndex = lowBit >> 5
    let shift = lowBit & 31
    let low = UInt64(words[wordIndex]) >> UInt64(shift)
    let high: UInt64
    if shift > 25 && wordIndex < 7 {
      high = UInt64(words[wordIndex + 1]) << UInt64(32 - shift)
    } else {
      high = 0
    }
    return (low | high) & 0x7F
  }

  static func widen(_ words: SIMD8<UInt32>) -> SIMD4<UInt64> {
    SIMD4<UInt64>(
      UInt64(words[0]) | (UInt64(words[1]) << 32),
      UInt64(words[2]) | (UInt64(words[3]) << 32),
      UInt64(words[4]) | (UInt64(words[5]) << 32),
      UInt64(words[6]) | (UInt64(words[7]) << 32)
    )
  }

  static func narrow(_ words: SIMD4<UInt64>) -> SIMD8<UInt32> {
    SIMD8<UInt32>(
      UInt32(truncatingIfNeeded: words[0]),
      UInt32(truncatingIfNeeded: words[0] >> 32),
      UInt32(truncatingIfNeeded: words[1]),
      UInt32(truncatingIfNeeded: words[1] >> 32),
      UInt32(truncatingIfNeeded: words[2]),
      UInt32(truncatingIfNeeded: words[2] >> 32),
      UInt32(truncatingIfNeeded: words[3]),
      UInt32(truncatingIfNeeded: words[3] >> 32)
    )
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static func montgomerySquare(_ value: SIMD4<UInt64>) -> SIMD4<UInt64> {
    // Arithmetic invariants:
    // - The input contains four initialized little-endian limbs below p.
    // - Six off-diagonal products are assembled as a seven-limb integer and
    //   doubled once before the four diagonal products are added.
    // - Every column sum fits UInt128, reducing a square from sixteen to ten
    //   64x64 multiplications without data-dependent carry control flow.
    // - All memory accesses and control flow are independent of field values.
    let cross01 = UInt128(value[0]) * UInt128(value[1])
    let cross02 = UInt128(value[0]) * UInt128(value[2])
    let cross03 = UInt128(value[0]) * UInt128(value[3])
    let cross12 = UInt128(value[1]) * UInt128(value[2])
    let cross13 = UInt128(value[1]) * UInt128(value[3])
    let cross23 = UInt128(value[2]) * UInt128(value[3])

    let cross1 = UInt64(truncatingIfNeeded: cross01)
    let cross2Sum = UInt128(UInt64(truncatingIfNeeded: cross01 >> 64))
      &+ UInt128(UInt64(truncatingIfNeeded: cross02))
    let cross2 = UInt64(truncatingIfNeeded: cross2Sum)
    let cross3Sum = UInt128(UInt64(truncatingIfNeeded: cross02 >> 64))
      &+ UInt128(UInt64(truncatingIfNeeded: cross03))
      &+ UInt128(UInt64(truncatingIfNeeded: cross12))
      &+ (cross2Sum >> 64)
    let cross3 = UInt64(truncatingIfNeeded: cross3Sum)
    let cross4Sum = UInt128(UInt64(truncatingIfNeeded: cross03 >> 64))
      &+ UInt128(UInt64(truncatingIfNeeded: cross12 >> 64))
      &+ UInt128(UInt64(truncatingIfNeeded: cross13))
      &+ (cross3Sum >> 64)
    let cross4 = UInt64(truncatingIfNeeded: cross4Sum)
    let cross5Sum = UInt128(UInt64(truncatingIfNeeded: cross13 >> 64))
      &+ UInt128(UInt64(truncatingIfNeeded: cross23))
      &+ (cross4Sum >> 64)
    let cross5 = UInt64(truncatingIfNeeded: cross5Sum)
    let cross6Sum = UInt128(UInt64(truncatingIfNeeded: cross23 >> 64))
      &+ (cross5Sum >> 64)
    let cross6 = UInt64(truncatingIfNeeded: cross6Sum)

    let doubled1 = cross1 << 1
    let doubled2 = (cross2 << 1) | (cross1 >> 63)
    let doubled3 = (cross3 << 1) | (cross2 >> 63)
    let doubled4 = (cross4 << 1) | (cross3 >> 63)
    let doubled5 = (cross5 << 1) | (cross4 >> 63)
    let doubled6 = (cross6 << 1) | (cross5 >> 63)
    let doubled7 = cross6 >> 63

    let diagonal0 = UInt128(value[0]) * UInt128(value[0])
    let diagonal1 = UInt128(value[1]) * UInt128(value[1])
    let diagonal2 = UInt128(value[2]) * UInt128(value[2])
    let diagonal3 = UInt128(value[3]) * UInt128(value[3])
    let limb0 = UInt64(truncatingIfNeeded: diagonal0)
    let limb1Sum = UInt128(doubled1)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal0 >> 64))
    let limb2Sum = UInt128(doubled2)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal1))
      &+ (limb1Sum >> 64)
    let limb3Sum = UInt128(doubled3)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal1 >> 64))
      &+ (limb2Sum >> 64)
    let limb4Sum = UInt128(doubled4)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal2))
      &+ (limb3Sum >> 64)
    let limb5Sum = UInt128(doubled5)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal2 >> 64))
      &+ (limb4Sum >> 64)
    let limb6Sum = UInt128(doubled6)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal3))
      &+ (limb5Sum >> 64)
    let limb7Sum = UInt128(doubled7)
      &+ UInt128(UInt64(truncatingIfNeeded: diagonal3 >> 64))
      &+ (limb6Sum >> 64)

    return reduceMontgomeryProduct(
      SIMD8<UInt64>(
        limb0,
        UInt64(truncatingIfNeeded: limb1Sum),
        UInt64(truncatingIfNeeded: limb2Sum),
        UInt64(truncatingIfNeeded: limb3Sum),
        UInt64(truncatingIfNeeded: limb4Sum),
        UInt64(truncatingIfNeeded: limb5Sum),
        UInt64(truncatingIfNeeded: limb6Sum),
        UInt64(truncatingIfNeeded: limb7Sum)
      ),
      highWord: UInt64(truncatingIfNeeded: limb7Sum >> 64)
    )
  }

  @inline(__always)
  private static func reduceMontgomeryProduct(
    _ product: SIMD8<UInt64>,
    highWord: UInt64
  ) -> SIMD4<UInt64> {
    var p0 = product[0]
    var p1 = product[1]
    var p2 = product[2]
    var p3 = product[3]
    var p4 = product[4]
    var p5 = product[5]
    var p6 = product[6]
    var p7 = product[7]
    var p8 = highWord
    var carry: UInt64
    var reduced: (words: SIMD4<UInt64>, carry: UInt64)
    var step: (value: UInt64, carry: UInt64)

    var factor = p0
    p0 = 0
    reduced = reduceMontgomeryLowLimb(factor, p1, p2, p3, p4)
    p1 = reduced.words[0]
    p2 = reduced.words[1]
    p3 = reduced.words[2]
    p4 = reduced.words[3]
    carry = reduced.carry
    step = addCarry(p5, carry: carry)
    p5 = step.value
    carry = step.carry
    step = addCarry(p6, carry: carry)
    p6 = step.value
    carry = step.carry
    step = addCarry(p7, carry: carry)
    p7 = step.value
    carry = step.carry
    p8 = addCarry(p8, carry: carry).value

    factor = p1
    p1 = 0
    reduced = reduceMontgomeryLowLimb(factor, p2, p3, p4, p5)
    p2 = reduced.words[0]
    p3 = reduced.words[1]
    p4 = reduced.words[2]
    p5 = reduced.words[3]
    carry = reduced.carry
    step = addCarry(p6, carry: carry)
    p6 = step.value
    carry = step.carry
    step = addCarry(p7, carry: carry)
    p7 = step.value
    carry = step.carry
    p8 = addCarry(p8, carry: carry).value

    factor = p2
    p2 = 0
    reduced = reduceMontgomeryLowLimb(factor, p3, p4, p5, p6)
    p3 = reduced.words[0]
    p4 = reduced.words[1]
    p5 = reduced.words[2]
    p6 = reduced.words[3]
    carry = reduced.carry
    step = addCarry(p7, carry: carry)
    p7 = step.value
    carry = step.carry
    p8 = addCarry(p8, carry: carry).value

    factor = p3
    reduced = reduceMontgomeryLowLimb(factor, p4, p5, p6, p7)
    p4 = reduced.words[0]
    p5 = reduced.words[1]
    p6 = reduced.words[2]
    p7 = reduced.words[3]
    carry = reduced.carry
    p8 = addCarry(p8, carry: carry).value

    return reduceP256(
      SIMD4<UInt64>(p4, p5, p6, p7),
      highWord: p8
    )
  }

  @inline(__always)
  private static func reduceMontgomeryLowLimb(
    _ factor: UInt64,
    _ word0: UInt64,
    _ word1: UInt64,
    _ word2: UInt64,
    _ word3: UInt64
  ) -> (words: SIMD4<UInt64>, carry: UInt64) {
    let shiftedLow = factor << 32
    let shiftedHigh = factor >> 32
    let highModulusProduct =
      (UInt128(factor) << 64)
      &- (UInt128(factor) << 32)
      &+ UInt128(factor)
    let differenceLow = UInt64(truncatingIfNeeded: highModulusProduct)
    let differenceHigh = UInt64(truncatingIfNeeded: highModulusProduct >> 64)
    let sum0 = UInt128(word0) &+ UInt128(shiftedLow)
    let sum1 = UInt128(word1) &+ UInt128(shiftedHigh) &+ (sum0 >> 64)
    let sum2 = UInt128(word2) &+ UInt128(differenceLow) &+ (sum1 >> 64)
    let sum3 = UInt128(word3) &+ UInt128(differenceHigh) &+ (sum2 >> 64)
    return (
      SIMD4<UInt64>(
        UInt64(truncatingIfNeeded: sum0),
        UInt64(truncatingIfNeeded: sum1),
        UInt64(truncatingIfNeeded: sum2),
        UInt64(truncatingIfNeeded: sum3)
      ),
      UInt64(truncatingIfNeeded: sum3 >> 64)
    )
  }

  @inline(__always)
  private static func addCarry(
    _ value: UInt64,
    carry: UInt64
  ) -> (value: UInt64, carry: UInt64) {
    let sum = UInt128(value) &+ UInt128(carry)
    return (
      UInt64(truncatingIfNeeded: sum),
      UInt64(truncatingIfNeeded: sum >> 64)
    )
  }

  #if arch(arm64) && canImport(Darwin)
    @inline(__always)
  #endif
  static func montgomeryMultiply(
    _ lhs: SIMD4<UInt64>,
    _ rhs: SIMD4<UInt64>
  ) -> SIMD4<UInt64> {
    // Arithmetic invariants:
    // - Both inputs contain four initialized little-endian limbs below p.
    // - Each integrated row contains one 256-bit product row plus at most one
    //   carry limb. The next reduction consumes the lowest limb before another
    //   row is accumulated, so no 512-bit intermediate storage is materialized.
    // - P-256 has Montgomery factor one. Its sparse modulus permits the lowest
    //   limb to be cancelled with shifts, additions, and subtractions only.
    // - All control flow and memory access are independent of field values.
    var accumulator = SIMD8<UInt64>(repeating: 0)
    accumulator = montgomeryMultiplyRow(lhs, rhs[0], accumulator: accumulator)
    accumulator = montgomeryMultiplyRow(lhs, rhs[1], accumulator: accumulator)
    accumulator = montgomeryMultiplyRow(lhs, rhs[2], accumulator: accumulator)
    accumulator = montgomeryMultiplyRow(lhs, rhs[3], accumulator: accumulator)
    return reduceP256(
      SIMD4<UInt64>(
        accumulator[0],
        accumulator[1],
        accumulator[2],
        accumulator[3]
      ),
      highWord: accumulator[4]
    )
  }

  @inline(__always)
  private static func montgomeryMultiplyRow(
    _ lhs: SIMD4<UInt64>,
    _ rhs: UInt64,
    accumulator: SIMD8<UInt64>
  ) -> SIMD8<UInt64> {
    let rhsWide = UInt128(rhs)
    let product0 = UInt128(accumulator[0]) &+ UInt128(lhs[0]) &* rhsWide
    let product1 = UInt128(accumulator[1])
      &+ UInt128(lhs[1]) &* rhsWide &+ (product0 >> 64)
    let product2 = UInt128(accumulator[2])
      &+ UInt128(lhs[2]) &* rhsWide &+ (product1 >> 64)
    let product3 = UInt128(accumulator[3])
      &+ UInt128(lhs[3]) &* rhsWide &+ (product2 >> 64)
    let product4 = UInt128(accumulator[4]) &+ (product3 >> 64)
    let product5 = UInt128(accumulator[5]) &+ (product4 >> 64)

    let reduced = reduceMontgomeryLowLimb(
      UInt64(truncatingIfNeeded: product0),
      UInt64(truncatingIfNeeded: product1),
      UInt64(truncatingIfNeeded: product2),
      UInt64(truncatingIfNeeded: product3),
      UInt64(truncatingIfNeeded: product4)
    )
    let upper = product5 &+ UInt128(reduced.carry)
    return SIMD8<UInt64>(
      reduced.words[0],
      reduced.words[1],
      reduced.words[2],
      reduced.words[3],
      UInt64(truncatingIfNeeded: upper),
      UInt64(truncatingIfNeeded: upper >> 64),
      0,
      0
    )
  }

  static func reduceP256(
    _ value: SIMD4<UInt64>,
    highWord: UInt64
  ) -> SIMD4<UInt64> {
    let modulus0: UInt64 = 0xFFFF_FFFF_FFFF_FFFF
    let modulus1: UInt64 = 0x0000_0000_FFFF_FFFF
    let modulus3: UInt64 = 0xFFFF_FFFF_0000_0001
    let candidate0 = value[0] &- modulus0
    let borrow0: UInt64 = value[0] < modulus0 ? 1 : 0
    let subtrahend1 = modulus1 &+ borrow0
    let candidate1 = value[1] &- subtrahend1
    let borrow1: UInt64 = value[1] < subtrahend1 ? 1 : 0
    let candidate2 = value[2] &- borrow1
    let borrow2: UInt64 = value[2] < borrow1 ? 1 : 0
    let subtrahend3 = modulus3 &+ borrow2
    let candidate3 = value[3] &- subtrahend3
    let borrow3: UInt64 = value[3] < subtrahend3 ? 1 : 0
    let highBorrow: UInt64 = highWord < borrow3 ? 1 : 0
    let useCandidate = UInt64(1) ^ highBorrow
    let mask = UInt64(0) &- useCandidate
    return SIMD4<UInt64>(
      (candidate0 & mask) | (value[0] & ~mask),
      (candidate1 & mask) | (value[1] & ~mask),
      (candidate2 & mask) | (value[2] & ~mask),
      (candidate3 & mask) | (value[3] & ~mask)
    )
  }

  @inline(__always)
  static func equalWordMask(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let difference = lhs ^ rhs
    let nonzero = (difference | (UInt64(0) &- difference)) >> 63
    return UInt64(0) &- (nonzero ^ 1)
  }

  static func nonzeroWideMask(_ words: SIMD4<UInt64>) -> UInt64 {
    var value: UInt64 = 0
    var index = 0
    while index < 4 {
      value |= words[index]
      index += 1
    }
    let nonzero = (value | (UInt64(0) &- value)) >> 63
    return UInt64(0) &- nonzero
  }

  static func selectWide(
    mask: UInt64,
    _ selected: SIMD4<UInt64>,
    _ alternative: SIMD4<UInt64>
  ) -> SIMD4<UInt64> {
    var result = SIMD4<UInt64>(repeating: 0)
    var index = 0
    while index < 4 {
      result[index] = (selected[index] & mask) | (alternative[index] & ~mask)
      index += 1
    }
    return result
  }

  static func decode(_ bytes: Span<UInt8>) -> SIMD8<UInt32> {
    var words = SIMD8<UInt32>(repeating: 0)
    var word = 0
    while word < 8 {
      let offset = bytes.count - (word + 1) * 4
      words[word] =
        (UInt32(bytes[offset]) << 24)
        | (UInt32(bytes[offset + 1]) << 16)
        | (UInt32(bytes[offset + 2]) << 8)
        | UInt32(bytes[offset + 3])
      word += 1
    }
    return words
  }

  static func decode(hex: String) -> SIMD8<UInt32> {
    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(hex.utf8.count / 2)
    var high: UInt8 = 0
    var haveHigh = false
    for character in hex.utf8 {
      let value: UInt8
      switch character {
      case 0x30...0x39: value = character - 0x30
      case 0x41...0x46: value = character - 0x41 + 10
      case 0x61...0x66: value = character - 0x61 + 10
      default: value = 0
      }
      if haveHigh {
        bytes.append((high << 4) | value)
        haveHigh = false
      } else {
        high = value
        haveHigh = true
      }
    }
    return decode(bytes.span)
  }

  static func encode(_ words: SIMD8<UInt32>) -> ContiguousArray<UInt8> {
    var bytes = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var word = 0
    while word < 8 {
      let offset = (7 - word) * 4
      let value = words[word]
      bytes[offset] = UInt8(truncatingIfNeeded: value >> 24)
      bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
      bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
      bytes[offset + 3] = UInt8(truncatingIfNeeded: value)
      word += 1
    }
    return bytes
  }

  static func compare(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> Int {
    var index = 7
    while index >= 0 {
      if lhs[index] != rhs[index] {
        return lhs[index] < rhs[index] ? -1 : 1
      }
      index -= 1
    }
    return 0
  }

  static func subtract(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let minuend = UInt64(lhs[index])
      let subtrahend = UInt64(rhs[index]) + borrow
      let difference = minuend &- subtrahend
      result[index] = UInt32(truncatingIfNeeded: difference)
      borrow = difference >> 63
      index += 1
    }
    return result
  }

  /// Reduces a nine-limb value known to be smaller than twice `modulus`.
  ///
  /// `highWord` is restricted to zero or one by every caller. The subtraction
  /// and selection execute for both outcomes so secret field values do not
  /// choose a control-flow path.
  static func reduce(
    _ value: SIMD8<UInt32>,
    highWord: UInt64,
    modulo modulus: SIMD8<UInt32>
  ) -> SIMD8<UInt32> {
    var candidate = SIMD8<UInt32>(repeating: 0)
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let difference = UInt64(value[index]) &- (UInt64(modulus[index]) + borrow)
      candidate[index] = UInt32(truncatingIfNeeded: difference)
      borrow = difference >> 63
      index += 1
    }
    let highDifference = highWord &- borrow
    let highBorrow = highDifference >> 63
    let useCandidate = UInt32(1) ^ UInt32(truncatingIfNeeded: highBorrow)
    return select(mask: UInt32(0) &- useCandidate, candidate, value)
  }

  static func equalMask(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> UInt32 {
    var difference: UInt32 = 0
    var index = 0
    while index < 8 {
      difference |= lhs[index] ^ rhs[index]
      index += 1
    }
    let nonzero = (difference | (UInt32(0) &- difference)) >> 31
    return UInt32(0) &- (nonzero ^ 1)
  }

  static func nonzeroMask(_ words: SIMD8<UInt32>) -> UInt32 {
    var value: UInt32 = 0
    var index = 0
    while index < 8 {
      value |= words[index]
      index += 1
    }
    let nonzero = (value | (UInt32(0) &- value)) >> 31
    return UInt32(0) &- nonzero
  }

  static func lessThanMask(
    _ lhs: SIMD8<UInt32>,
    _ rhs: SIMD8<UInt32>
  ) -> UInt32 {
    var borrow: UInt64 = 0
    var index = 0
    while index < 8 {
      let difference = UInt64(lhs[index]) &- (UInt64(rhs[index]) + borrow)
      borrow = difference >> 63
      index += 1
    }
    return UInt32(0) &- UInt32(truncatingIfNeeded: borrow)
  }

  static func select(
    mask: UInt32,
    _ selected: SIMD8<UInt32>,
    _ alternative: SIMD8<UInt32>
  ) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var index = 0
    while index < 8 {
      result[index] = (selected[index] & mask) | (alternative[index] & ~mask)
      index += 1
    }
    return result
  }

  static func add(_ lhs: SIMD8<UInt32>, _ rhs: SIMD8<UInt32>) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var carry: UInt64 = 0
    var index = 0
    while index < 8 {
      let sum = UInt64(lhs[index]) + UInt64(rhs[index]) + carry
      result[index] = UInt32(truncatingIfNeeded: sum)
      carry = sum >> 32
      index += 1
    }
    return result
  }

  static func truncate(_ words: [UInt64]) -> SIMD8<UInt32> {
    var result = SIMD8<UInt32>(repeating: 0)
    var index = 0
    while index < 8 {
      result[index] = UInt32(truncatingIfNeeded: words[index])
      index += 1
    }
    return result
  }
}
