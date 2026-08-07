import SSLCore

/// Typed failures shared by the NIST P-384 and P-521 private-key generators.
public enum WeierstrassKeyGenerationError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case invalidScalar
}

public typealias P384KeyGenerationError = WeierstrassKeyGenerationError
public typealias P521KeyGenerationError = WeierstrassKeyGenerationError

public struct P384SharedSecret: ~Copyable, Sendable {
  public static let byteCount = 48
  private let storage: SecretBytes

  init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }
}

public struct P521SharedSecret: ~Copyable, Sendable {
  public static let byteCount = 66
  private let storage: SecretBytes

  init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }
}

public struct P384PrivateKey: InPlacePublicKeyDerivation, ~Copyable, Sendable {
  public static let byteCount = 48
  public static let publicKeyByteCount = P384PublicKey.uncompressedByteCount
  private static let maximumGenerationAttempts = 256
  private let storage: SecretBytes

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    guard WeierstrassECDSA.isValidSecretScalar(bytes, curve: .p384) else {
      throw .nonCanonicalEncoding
    }
    storage = Self.copyValidatedScalar(bytes)
  }

  private init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(P384KeyGenerationError) -> P384PrivateKey {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(Self.byteCount)
    } catch {
      preconditionFailure("P-384 private-key size is a compile-time constant")
    }
    var attempt = 0
    while attempt < maximumGenerationAttempts {
      let candidate: SecretBytes
      do {
        candidate = try SecretBytes(randomByteCount: byteCount, using: entropy)
      } catch let error {
        throw .entropy(error)
      }
      let accepted = candidate.withBorrowedBytes { bytes in
        WeierstrassECDSA.isValidSecretScalar(bytes, curve: .p384)
      }
      if accepted { return P384PrivateKey(consuming: candidate) }
      attempt += 1
    }
    throw .invalidScalar
  }

  public static func generate() throws(P384KeyGenerationError) -> P384PrivateKey {
    try generate(using: SystemEntropySource())
  }

  public borrowing func publicKey() -> P384PublicKey {
    let point = withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        .generator(.p384), scalar: scalar, curve: .p384
      )
    }
    let encoded = point.encoded(curve: .p384)!
    return P384PublicKey(consumingValidatedBytes: consume encoded, point: point)
  }

  public borrowing func publicKey(
    into destination: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard destination.count == Self.publicKeyByteCount else {
      throw .invalidOutputLength(expected: Self.publicKeyByteCount, actual: destination.count)
    }
    let point = withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        .generator(.p384), scalar: scalar, curve: .p384
      )
    }
    guard let encoded = point.encoded(curve: .p384) else {
      throw .invalidSignature
    }
    var index = 0
    while index < encoded.count { destination[index] = encoded[index]; index += 1 }
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }

  private static func copyValidatedScalar(_ bytes: Span<UInt8>) -> SecretBytes {
    let count: SecretByteCount
    do { count = try SecretByteCount(Self.byteCount) }
    catch { preconditionFailure("P-384 private-key size is a compile-time constant") }
    return SecretBytes(byteCount: count) { destination in
      var index = 0
      while index < Self.byteCount { destination[index] = bytes[index]; index += 1 }
    }
  }
}

public struct P521PrivateKey: InPlacePublicKeyDerivation, ~Copyable, Sendable {
  public static let byteCount = 66
  public static let publicKeyByteCount = P521PublicKey.uncompressedByteCount
  private static let maximumGenerationAttempts = 256
  private let storage: SecretBytes

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    guard WeierstrassECDSA.isValidSecretScalar(bytes, curve: .p521) else {
      throw .nonCanonicalEncoding
    }
    storage = Self.copyValidatedScalar(bytes)
  }

  private init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(P521KeyGenerationError) -> P521PrivateKey {
    let byteCount: SecretByteCount
    do { byteCount = try SecretByteCount(Self.byteCount) }
    catch { preconditionFailure("P-521 private-key size is a compile-time constant") }
    var attempt = 0
    while attempt < maximumGenerationAttempts {
      var candidate: SecretBytes
      do { candidate = try SecretBytes(randomByteCount: byteCount, using: entropy) }
      catch let error { throw .entropy(error) }
      candidate.withMutableBorrowedBytes { bytes in
        bytes[0] &= 0x01
      }
      let accepted = candidate.withBorrowedBytes { bytes in
        WeierstrassECDSA.isValidSecretScalar(bytes, curve: .p521)
      }
      if accepted { return P521PrivateKey(consuming: candidate) }
      attempt += 1
    }
    throw .invalidScalar
  }

  public static func generate() throws(P521KeyGenerationError) -> P521PrivateKey {
    try generate(using: SystemEntropySource())
  }

  public borrowing func publicKey() -> P521PublicKey {
    let point = withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        .generator(.p521), scalar: scalar, curve: .p521
      )
    }
    let encoded = point.encoded(curve: .p521)!
    return P521PublicKey(consumingValidatedBytes: consume encoded, point: point)
  }

  public borrowing func publicKey(
    into destination: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard destination.count == Self.publicKeyByteCount else {
      throw .invalidOutputLength(expected: Self.publicKeyByteCount, actual: destination.count)
    }
    let point = withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        .generator(.p521), scalar: scalar, curve: .p521
      )
    }
    guard let encoded = point.encoded(curve: .p521) else { throw .invalidSignature }
    var index = 0
    while index < encoded.count { destination[index] = encoded[index]; index += 1 }
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }

  private static func copyValidatedScalar(_ bytes: Span<UInt8>) -> SecretBytes {
    let count: SecretByteCount
    do { count = try SecretByteCount(Self.byteCount) }
    catch { preconditionFailure("P-521 private-key size is a compile-time constant") }
    return SecretBytes(byteCount: count) { destination in
      var index = 0
      while index < Self.byteCount { destination[index] = bytes[index]; index += 1 }
    }
  }
}

public struct P384KeyPair: ~Copyable, Sendable {
  public let publicKey: P384PublicKey
  public let privateKey: P384PrivateKey

  public init(privateKey: consuming P384PrivateKey) {
    publicKey = privateKey.publicKey()
    self.privateKey = privateKey
  }

  public static func generate(using entropy: borrowing any EntropySource)
    throws(P384KeyGenerationError) -> P384KeyPair {
    P384KeyPair(privateKey: try P384PrivateKey.generate(using: entropy))
  }

  public static func generate() throws(P384KeyGenerationError) -> P384KeyPair {
    P384KeyPair(privateKey: try P384PrivateKey.generate())
  }
}

public struct P521KeyPair: ~Copyable, Sendable {
  public let publicKey: P521PublicKey
  public let privateKey: P521PrivateKey

  public init(privateKey: consuming P521PrivateKey) {
    publicKey = privateKey.publicKey()
    self.privateKey = privateKey
  }

  public static func generate(using entropy: borrowing any EntropySource)
    throws(P521KeyGenerationError) -> P521KeyPair {
    P521KeyPair(privateKey: try P521PrivateKey.generate(using: entropy))
  }

  public static func generate() throws(P521KeyGenerationError) -> P521KeyPair {
    P521KeyPair(privateKey: try P521PrivateKey.generate())
  }
}

public enum P384KeyAgreement: InPlaceKeyAgreement, InPlaceEncodedKeyAgreement {
  public typealias PublicKey = P384PublicKey
  public typealias PrivateKey = P384PrivateKey
  public typealias SharedSecret = P384SharedSecret
  public static let sharedSecretByteCount = P384SharedSecret.byteCount

  public static func sharedSecret(
    privateKey: borrowing P384PrivateKey,
    peerPublicKey: borrowing P384PublicKey
  ) throws(CryptoInputError) -> P384SharedSecret {
    let count: SecretByteCount
    do { count = try SecretByteCount(sharedSecretByteCount) }
    catch { preconditionFailure("P-384 shared-secret size is a compile-time constant") }
    let secret = try SecretBytes(byteCount: count) { destination throws(CryptoInputError) in
      try sharedSecret(privateKey: privateKey, peerPublicKey: peerPublicKey, into: &destination)
    }
    return P384SharedSecret(consuming: secret)
  }

  public static func sharedSecret(
    privateKey: borrowing P384PrivateKey,
    peerPublicKey: borrowing P384PublicKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard sharedSecret.count == sharedSecretByteCount else {
      throw .invalidOutputLength(expected: sharedSecretByteCount, actual: sharedSecret.count)
    }
    let point = privateKey.withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: P384PrivateKey.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        peerPublicKey.point, scalar: scalar, curve: .p384
      )
    }
    guard let affine = point.affine(curve: .p384) else { throw .invalidPeerKey }
    let encoded = affine.x.encoded(byteCount: sharedSecretByteCount)
    var index = 0
    while index < encoded.count { sharedSecret[index] = encoded[index]; index += 1 }
  }

  public static func sharedSecret(
    privateKey: borrowing P384PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    let publicKey = try P384PublicKey(bytes: peerPublicKeyBytes)
    try P384KeyAgreement.sharedSecret(privateKey: privateKey, peerPublicKey: publicKey, into: &sharedSecret)
  }
}

public enum P521KeyAgreement: InPlaceKeyAgreement, InPlaceEncodedKeyAgreement {
  public typealias PublicKey = P521PublicKey
  public typealias PrivateKey = P521PrivateKey
  public typealias SharedSecret = P521SharedSecret
  public static let sharedSecretByteCount = P521SharedSecret.byteCount

  public static func sharedSecret(
    privateKey: borrowing P521PrivateKey,
    peerPublicKey: borrowing P521PublicKey
  ) throws(CryptoInputError) -> P521SharedSecret {
    let count: SecretByteCount
    do { count = try SecretByteCount(sharedSecretByteCount) }
    catch { preconditionFailure("P-521 shared-secret size is a compile-time constant") }
    let secret = try SecretBytes(byteCount: count) { destination throws(CryptoInputError) in
      try sharedSecret(privateKey: privateKey, peerPublicKey: peerPublicKey, into: &destination)
    }
    return P521SharedSecret(consuming: secret)
  }

  public static func sharedSecret(
    privateKey: borrowing P521PrivateKey,
    peerPublicKey: borrowing P521PublicKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard sharedSecret.count == sharedSecretByteCount else {
      throw .invalidOutputLength(expected: sharedSecretByteCount, actual: sharedSecret.count)
    }
    let point = privateKey.withBorrowedBytes { bytes in
      var scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: P521PrivateKey.byteCount)
      defer { scalar.wipe() }
      return WeierstrassECDSA.Point.scalarMultiplySecret(
        peerPublicKey.point, scalar: scalar, curve: .p521
      )
    }
    guard let affine = point.affine(curve: .p521) else { throw .invalidPeerKey }
    let encoded = affine.x.encoded(byteCount: sharedSecretByteCount)
    var index = 0
    while index < encoded.count { sharedSecret[index] = encoded[index]; index += 1 }
  }

  public static func sharedSecret(
    privateKey: borrowing P521PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    let publicKey = try P521PublicKey(bytes: peerPublicKeyBytes)
    try P521KeyAgreement.sharedSecret(privateKey: privateKey, peerPublicKey: publicKey, into: &sharedSecret)
  }
}

extension WeierstrassECDSA {
  static func isValidSecretScalar(_ bytes: Span<UInt8>, curve: Curve) -> Bool {
    guard bytes.count == curve.byteCount else { return false }
    let scalar = FixedUInt(bytes: bytes, byteCount: curve.byteCount)
    return !scalar.isZero && scalar < curve.order
  }
}

extension P384PublicKey {
  init(consumingValidatedBytes bytes: consuming ContiguousArray<UInt8>, point: WeierstrassECDSA.Point) {
    storage = OwnedBytes(consuming: bytes)
    self.point = point
  }
}

extension P521PublicKey {
  init(consumingValidatedBytes bytes: consuming ContiguousArray<UInt8>, point: WeierstrassECDSA.Point) {
    storage = OwnedBytes(consuming: bytes)
    self.point = point
  }
}
