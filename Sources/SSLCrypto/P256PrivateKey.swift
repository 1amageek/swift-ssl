import SSLCore

/// A uniquely owned P-256 private scalar for DHKEM operations.
///
/// The scalar remains in wiped storage. Secret point multiplication consumes
/// it only through a synchronous immutable borrow with fixed control flow.
public struct P256PrivateKey: InPlacePublicKeyDerivation, ~Copyable, Sendable {
  public static let byteCount = 32
  public static let publicKeyByteCount = P256PublicKey.uncompressedByteCount
  private static let maximumGenerationAttempts = 256

  private let storage: SecretBytes

  public init(bytes: Span<UInt8>) throws(CryptoInputError) {
    guard bytes.count == Self.byteCount else {
      throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
    }
    guard P256Point.isValidSecretScalar(bytes) else {
      throw .nonCanonicalEncoding
    }
    storage = Self.copyValidatedScalar(bytes)
  }

  private init(consuming storage: consuming SecretBytes) {
    self.storage = storage
  }

  public static func generate(
    using entropy: borrowing any EntropySource
  ) throws(P256KeyGenerationError) -> P256PrivateKey {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(Self.byteCount)
    } catch {
      preconditionFailure("P-256 private-key size is a compile-time constant")
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
        P256Point.isValidSecretScalar(bytes)
      }
      if accepted {
        return P256PrivateKey(consuming: candidate)
      }
      attempt += 1
    }
    throw .invalidScalar
  }

  public static func generate() throws(P256KeyGenerationError) -> P256PrivateKey {
    try generate(using: SystemEntropySource())
  }

  public borrowing func publicKey() -> P256PublicKey {
    let point = withBorrowedBytes { scalar in
      P256Point.scalarMultiplyGeneratorSecret(scalar: scalar)
    }
    var encoded = ContiguousArray<UInt8>(
      repeating: 0,
      count: P256PublicKey.uncompressedByteCount
    )
    var destination = encoded.mutableSpan
    point.writeUncompressedAssumingFinite(into: &destination)
    return P256PublicKey(
      consumingValidatedBytes: consume encoded,
      point: point
    )
  }

  public borrowing func publicKey(
    into destination: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard destination.count == Self.publicKeyByteCount else {
      throw .invalidOutputLength(
        expected: Self.publicKeyByteCount,
        actual: destination.count
      )
    }
    let point = withBorrowedBytes { scalar in
      P256Point.scalarMultiplyGeneratorSecret(scalar: scalar)
    }
    point.writeUncompressedAssumingFinite(into: &destination)
  }

  /// Borrows the private scalar for the duration of `body`.
  ///
  /// The span is scoped to the call and cannot escape. The key remains the
  /// sole owner of the allocation and wipes it exactly once on destruction.
  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes(body)
  }

  private static func copyValidatedScalar(_ bytes: Span<UInt8>) -> SecretBytes {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(Self.byteCount)
    } catch {
      preconditionFailure("P-256 private-key size is a compile-time constant")
    }
    return SecretBytes(byteCount: byteCount) { destination in
      var index = 0
      while index < Self.byteCount {
        destination[index] = bytes[index]
        index += 1
      }
    }
  }
}
