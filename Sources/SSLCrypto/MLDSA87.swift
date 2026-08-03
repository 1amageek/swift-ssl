import SSLCore

/// FIPS 204 ML-DSA-87 signing and verification.
public enum MLDSA87: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA87PublicKey
  public typealias PrivateKey = MLDSA87PrivateKey

  public static let seedByteCount = 32
  public static let publicKeyByteCount = 2_592
  public static let privateKeyByteCount = 4_896
  public static let signatureByteCount = 4_627
  public static let randomizerByteCount = 32
  public static let maximumContextByteCount = 255

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA87KeyPair {
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
    let privateKey = try MLDSA87PrivateKey(seedStorage: consume seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA87KeyPair(publicKey: publicKey, privateKey: privateKey)
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA87KeyPair {
    try keyPair(using: SystemEntropySource())
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA87KeyPair {
    let privateKey = try MLDSA87PrivateKey(seed: seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA87KeyPair(publicKey: publicKey, privateKey: privateKey)
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey,
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
    using privateKey: borrowing MLDSA87PrivateKey
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
    using privateKey: borrowing MLDSA87PrivateKey,
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
    using privateKey: borrowing MLDSA87PrivateKey,
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
    using publicKey: borrowing MLDSA87PublicKey
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
    return try MLDSACore(parameterSet: .mlDSA87).verify(
      signature: signature,
      message: message,
      context: context,
      publicKey: publicKey.expanded
    )
  }

  package static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA87PrivateKey,
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
