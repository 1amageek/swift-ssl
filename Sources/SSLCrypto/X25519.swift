import SSLCore

/// RFC 7748 X25519 key agreement using a fixed-radix field implementation.
public enum X25519: InPlaceKeyAgreement, InPlaceEncodedKeyAgreement {
  public typealias PublicKey = X25519PublicKey
  public typealias PrivateKey = X25519PrivateKey
  public typealias SharedSecret = X25519SharedSecret
  public static let sharedSecretByteCount = X25519SharedSecret.byteCount

  public static func sharedSecret(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey
  ) throws(CryptoInputError) -> X25519SharedSecret {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(X25519SharedSecret.byteCount)
    } catch {
      throw .invalidPeerKey
    }
    let secret = try SecretBytes(byteCount: byteCount) {
      destination throws(CryptoInputError) in
      try sharedSecret(
        privateKey: privateKey,
        peerPublicKey: peerPublicKey,
        into: &destination
      )
    }
    return X25519SharedSecret(consuming: secret)
  }

  public static func sharedSecret(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try peerPublicKey.withBorrowedBytes { peer throws(CryptoInputError) in
      try Self.sharedSecret(
        privateKey: privateKey,
        peerPublicKeyBytes: peer,
        into: &sharedSecret
      )
    }
  }

  public static func sharedSecret(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard peerPublicKeyBytes.count == X25519PublicKey.byteCount else {
      throw .invalidLength(
        expected: X25519PublicKey.byteCount,
        actual: peerPublicKeyBytes.count
      )
    }
    guard sharedSecret.count == sharedSecretByteCount else {
      throw .invalidLength(
        expected: sharedSecretByteCount,
        actual: sharedSecret.count
      )
    }
    let accepted = privateKey.withBorrowedBytes { scalar in
      X25519Montgomery.scalarMultiply(
        scalar: scalar,
        uCoordinate: peerPublicKeyBytes,
        into: &sharedSecret
      )
    }
    guard accepted else {
      throw .invalidPeerKey
    }
  }
}

public struct X25519PrivateKey: InPlacePublicKeyDerivation, ~Copyable, Sendable {
  public static let byteCount = 32
  public static let publicKeyByteCount = X25519PublicKey.byteCount
  private let storage: SecretBytes

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(X25519KeyGenerationError) -> X25519PrivateKey {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(Self.byteCount)
    } catch {
      throw .memoryFailure
    }
    let storage: SecretBytes
    do {
      storage = try SecretBytes(
        randomByteCount: byteCount,
        using: entropy
      )
    } catch {
      throw .entropy(error)
    }
    return X25519PrivateKey(consuming: storage)
  }

  public static func generate() throws(X25519KeyGenerationError) -> X25519PrivateKey {
    let entropy = SystemEntropySource()
    return try Self.generate(using: entropy)
  }

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    do {
      storage = try SecretBytes(copying: bytes)
    } catch {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
  }

  private init(consuming storage: consuming SecretBytes) {
    self.storage = consume storage
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }

  public borrowing func publicKey() -> X25519PublicKey {
    let bytes = withBorrowedBytes { scalar in
      X25519Montgomery.scalarMultiplyBase(scalar: scalar)
    }
    return X25519PublicKey(uncheckedBytes: bytes)
  }

  public borrowing func publicKey(
    into destination: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard destination.count == Self.publicKeyByteCount else {
      throw .invalidLength(
        expected: Self.publicKeyByteCount,
        actual: destination.count
      )
    }
    withBorrowedBytes { scalar in
      X25519FixedBase.scalarMultiply(
        scalar: scalar,
        into: &destination
      )
    }
  }
}

public struct X25519PublicKey: Sendable, Equatable {
  public static let byteCount = 32
  private let storage: OwnedBytes

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    storage = OwnedBytes(copying: bytes)
  }

  fileprivate init(uncheckedBytes bytes: ContiguousArray<UInt8>) {
    storage = OwnedBytes(consuming: bytes)
  }

  public var span: Span<UInt8> { storage.span }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(storage.span)
  }
}

public struct X25519SharedSecret: ~Copyable, Sendable {
  public static let byteCount = 32
  private let storage: SecretBytes

  fileprivate init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }
}

private enum X25519Montgomery {
  static func scalarMultiplyBase(scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
    X25519FixedBase.scalarMultiply(scalar: scalar)
  }

  static func scalarMultiply(
    scalar: Span<UInt8>,
    uCoordinate: Span<UInt8>,
    into destination: inout MutableSpan<UInt8>
  ) -> Bool {
    scalarMultiplyField(scalar: scalar, uCoordinate: uCoordinate)
      .encodeIfNonZero(into: &destination)
  }

  private static func scalarMultiplyField(
    scalar: Span<UInt8>,
    uCoordinate: Span<UInt8>
  ) -> X25519FieldElement {
    precondition(scalar.count == X25519PrivateKey.byteCount)
    // Unsafe boundary invariants:
    // - The length precondition proves that four unaligned UInt64 loads stay
    //   within initialized scalar storage retained for this synchronous borrow.
    // - The raw pointer is neither rebound nor retained outside the closure.
    // - Explicit little-endian conversion preserves RFC 7748 scalar semantics.
    let scalarWords: (UInt64, UInt64, UInt64, UInt64) = scalar.withUnsafeBytes {
      bytes in
      let baseAddress = bytes.baseAddress.unsafelyUnwrapped
      return (
        UInt64(littleEndian: baseAddress.loadUnaligned(as: UInt64.self)),
        UInt64(
          littleEndian: baseAddress.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
        ),
        UInt64(
          littleEndian: baseAddress.loadUnaligned(fromByteOffset: 16, as: UInt64.self)
        ),
        UInt64(
          littleEndian: baseAddress.loadUnaligned(fromByteOffset: 24, as: UInt64.self)
        )
      )
    }
    let x1 = X25519FieldElement(bytes: uCoordinate)
    var x2 = X25519FieldElement(one: true)
    var z2 = X25519FieldElement()
    var x3 = x1
    var z3 = X25519FieldElement(one: true)
    var swap: UInt64 = 0
    // Clamp in registers and consume each source word once. This avoids a
    // byte load for every ladder bit without materializing a secret buffer.
    var scalarWord = (scalarWords.3 & 0x7fff_ffff_ffff_ffff) | (UInt64(1) << 62)
    var scalarBit = 62
    var scalarWordIndex = 3
    var remainingBits = 255
    while remainingBits > 0 {
      let bitValue = (scalarWord >> scalarBit) & 1
      swap ^= bitValue
      X25519FieldElement.conditionalSwap(&x2, &x3, swap)
      X25519FieldElement.conditionalSwap(&z2, &z3, swap)
      swap = bitValue

      // Reuse four field temporaries so the five-limb values remain in
      // registers across a ladder step instead of creating spill-heavy
      // expression intermediates.
      var difference3 = x3 - z3
      var difference2 = x2 - z2
      var sum2 = x2 + z2
      var sum3 = x3 + z3
      difference3 = difference3 * sum2
      sum3 = sum3 * difference2
      difference2 = difference2.squared()
      sum2 = sum2.squared()
      x3 = difference3 + sum3
      sum3 = difference3 - sum3
      x2 = sum2 * difference2
      sum2 = sum2 - difference2
      sum3 = sum3.squared()
      difference3 = sum2.multiplied(bySmall: 121666)
      x3 = x3.squared()
      difference2 = difference2 + difference3
      z3 = x1 * sum3
      z2 = sum2 * difference2
      remainingBits -= 1
      if scalarBit == 0, remainingBits > 0 {
        scalarWordIndex -= 1
        switch scalarWordIndex {
        case 2:
          scalarWord = scalarWords.2
        case 1:
          scalarWord = scalarWords.1
        default:
          scalarWord = scalarWords.0 & ~UInt64(7)
        }
        scalarBit = 63
      } else {
        scalarBit -= 1
      }
    }
    X25519FieldElement.conditionalSwap(&x2, &x3, swap)
    X25519FieldElement.conditionalSwap(&z2, &z3, swap)
    return x2 * z2.inverted()
  }

}
