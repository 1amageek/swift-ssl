import SwiftSSLCore

/// FIPS 204 ML-DSA-65 signing and verification.
public enum MLDSA65: InPlaceContextualRandomizedDigitalSignature {
  public typealias PublicKey = MLDSA65PublicKey
  public typealias PrivateKey = MLDSA65PrivateKey

  public static let seedByteCount = 32
  public static let publicKeyByteCount = 1_952
  public static let privateKeyByteCount = 4_032
  public static let signatureByteCount = 3_309
  public static let randomizerByteCount = 32
  public static let maximumContextByteCount = 255

  public static func keyPair(
    using entropy: borrowing any EntropySource
  ) throws(MLDSAError) -> MLDSA65KeyPair {
    let seed: SecretBytes
    do {
      seed = try SecretBytes(
        randomByteCount: try SecretByteCount(Self.seedByteCount),
        using: entropy
      )
    } catch let error as EntropyError {
      throw .entropy(error)
    } catch let error as SecretMemoryError {
      throw .secretMemory(error)
    } catch {
      throw .inputTooLong
    }
    let privateKey = try MLDSA65PrivateKey(seedStorage: consume seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA65KeyPair(
      publicKey: publicKey,
      privateKey: privateKey
    )
  }

  public static func keyPair() throws(MLDSAError) -> MLDSA65KeyPair {
    try keyPair(using: SystemEntropySource())
  }

  public static func keyPair(seed: Span<UInt8>) throws(MLDSAError) -> MLDSA65KeyPair {
    let privateKey = try MLDSA65PrivateKey(seed: seed)
    let publicKey = try privateKey.publicKey()
    return MLDSA65KeyPair(
      publicKey: publicKey,
      privateKey: privateKey
    )
  }

  public static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA65PrivateKey,
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
    using privateKey: borrowing MLDSA65PrivateKey
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
    using privateKey: borrowing MLDSA65PrivateKey,
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

    let randomizer: SecretBytes
    do {
      randomizer = try SecretBytes(
        randomByteCount: try SecretByteCount(Self.randomizerByteCount),
        using: entropy
      )
    } catch let error as EntropyError {
      throw .entropy(error)
    } catch let error as SecretMemoryError {
      throw .secretMemory(error)
    } catch {
      throw .inputTooLong
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
    using privateKey: borrowing MLDSA65PrivateKey,
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
    using publicKey: borrowing MLDSA65PublicKey
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
    return try MLDSA65Core.verify(
      signature: signature,
      message: message,
      context: context,
      publicKey: publicKey.expanded
    )
  }

  package static func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    using privateKey: borrowing MLDSA65PrivateKey,
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
