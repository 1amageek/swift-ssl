import SSLCore

/// FIPS 204 ML-DSA-44 signing and verification.
public enum MLDSA44: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA44PublicKey
  public typealias PrivateKey = MLDSA44PrivateKey

  public static let seedByteCount = 32
  public static let publicKeyByteCount = 1_312
  public static let privateKeyByteCount = 2_560
  public static let signatureByteCount = 2_420
  public static let randomizerByteCount = 32
  public static let maximumContextByteCount = 255

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA44KeyPair {
    let seedByteCount: SecretByteCount
    do {
      seedByteCount = try SecretByteCount(Self.seedByteCount)
    } catch {
      throw .secretMemory(error)
    }
    let seed: SecretBytes
    do {
      seed = try SecretBytes(
        randomByteCount: seedByteCount,
        using: entropy
      )
    } catch {
      throw .entropy(error)
    }
    let privateKey = try MLDSA44PrivateKey(seedStorage: consume seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA44KeyPair(publicKey: publicKey, privateKey: privateKey)
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA44KeyPair {
    try keyPair(using: SystemEntropySource())
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA44KeyPair {
    let privateKey = try MLDSA44PrivateKey(seed: seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA44KeyPair(publicKey: publicKey, privateKey: privateKey)
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey,
    entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    var signature = ContiguousArray<UInt8>(
      repeating: 0,
      count: Self.signatureByteCount
    )
    var output = signature.mutableSpan
    try sign(
      message: message,
      context: context,
      using: privateKey,
      entropy: entropy,
      into: &output
    )
    return signature
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try sign(
      message: message,
      context: context,
      using: privateKey,
      entropy: SystemEntropySource()
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey,
    entropy: borrowing any EntropySource,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    guard context.count <= Self.maximumContextByteCount else {
      throw .contextTooLong(limit: Self.maximumContextByteCount, actual: context.count)
    }
    guard signature.count == Self.signatureByteCount else {
      throw .invalidSignatureOutputLength(
        expected: Self.signatureByteCount,
        actual: signature.count
      )
    }

    let randomizerByteCount: SecretByteCount
    do {
      randomizerByteCount = try SecretByteCount(Self.randomizerByteCount)
    } catch {
      throw .secretMemory(error)
    }
    let randomizer: SecretBytes
    do {
      randomizer = try SecretBytes(
        randomByteCount: randomizerByteCount,
        using: entropy
      )
    } catch {
      throw .entropy(error)
    }

    try privateKey.sign(
      message: message,
      context: context,
      randomizer: randomizer,
      into: &signature
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try sign(
      message: message,
      context: context,
      using: privateKey,
      entropy: SystemEntropySource(),
      into: &signature
    )
  }

  public static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    context: Span<UInt8>,
    using publicKey: borrowing MLDSA44PublicKey
  ) throws(MLDSAError) -> Bool {
    guard signature.count == Self.signatureByteCount else {
      throw .invalidSignatureLength(
        expected: Self.signatureByteCount,
        actual: signature.count
      )
    }
    guard context.count <= Self.maximumContextByteCount else {
      throw .contextTooLong(limit: Self.maximumContextByteCount, actual: context.count)
    }
    return try MLDSACore(parameterSet: .mlDSA44).verify(
      signature: signature,
      message: message,
      context: context,
      publicKey: publicKey.expanded
    )
  }

  package static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA44PrivateKey,
    randomizer: Span<UInt8>
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    guard randomizer.count == Self.randomizerByteCount else {
      throw .invalidSeedLength(expected: Self.randomizerByteCount, actual: randomizer.count)
    }
    guard context.count <= Self.maximumContextByteCount else {
      throw .contextTooLong(limit: Self.maximumContextByteCount, actual: context.count)
    }
    return try privateKey.sign(
      message: message,
      context: context,
      randomizer: randomizer
    )
  }
}
