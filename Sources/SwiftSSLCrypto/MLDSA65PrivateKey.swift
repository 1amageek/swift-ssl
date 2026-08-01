import SwiftSSLCore

/// A noncopyable owner for a FIPS 204 ML-DSA-65 private key.
public struct MLDSA65PrivateKey: ~Copyable, Sendable {
  public static let byteCount = MLDSA65.privateKeyByteCount
  public static let seedByteCount = MLDSA65.seedByteCount

  private let storage: SecretBytes
  private let storageKind: StorageKind
  private let encodedPublicKey: MLDSA65PublicKey
  private let expanded: MLDSA65ExpandedPrivateKey

  private enum StorageKind: Sendable {
    case seed
    case standardRepresentation
  }

  public init(seed: Span<UInt8>) throws(MLDSAError) {
    guard seed.count == Self.seedByteCount else {
      throw .invalidSeedLength(expected: Self.seedByteCount, actual: seed.count)
    }
    let generated = try MLDSA65Core.keyGenerate(seed: seed)
    let publicKey = MLDSA65PublicKey(
      owned: generated.publicKey,
      expanded: generated.expandedPublicKey
    )
    let secretStorage: SecretBytes
    do {
      secretStorage = try SecretBytes(copying: seed)
    } catch {
      throw .secretMemory(error)
    }
    storage = secretStorage
    storageKind = .seed
    encodedPublicKey = publicKey
    expanded = generated.expandedPrivateKey
  }

  package init(seedStorage: consuming SecretBytes) throws(MLDSAError) {
    guard seedStorage.count == Self.seedByteCount else {
      throw .invalidSeedLength(expected: Self.seedByteCount, actual: seedStorage.count)
    }
    let generated = try seedStorage.withBorrowedBytes {
      seed throws(MLDSAError) in
      try MLDSA65Core.keyGenerate(seed: seed)
    }
    let publicKey = MLDSA65PublicKey(
      owned: generated.publicKey,
      expanded: generated.expandedPublicKey
    )
    storage = consume seedStorage
    storageKind = .seed
    encodedPublicKey = publicKey
    expanded = generated.expandedPrivateKey
  }

  public init(encoded: Span<UInt8>) throws(MLDSAError) {
    guard encoded.count == Self.byteCount else {
      throw .invalidPrivateKeyLength(expected: Self.byteCount, actual: encoded.count)
    }
    let validated = try MLDSA65Core.validatePrivateKeyAndDerivePublicKey(encoded)
    let publicKey = MLDSA65PublicKey(
      owned: validated.0,
      expanded: validated.1
    )
    let secretStorage: SecretBytes
    do {
      secretStorage = try SecretBytes(copying: encoded)
    } catch {
      throw .secretMemory(error)
    }
    storage = secretStorage
    storageKind = .standardRepresentation
    encodedPublicKey = publicKey
    expanded = validated.2
  }

  public borrowing func publicKey() throws(MLDSAError) -> MLDSA65PublicKey {
    encodedPublicKey
  }

  public borrowing func standardRepresentation() throws(MLDSAError) -> SecretBytes {
    switch storageKind {
    case .seed:
      return try MLDSA65Core.standardPrivateKeyRepresentation(
        privateKey: expanded,
        publicKey: encodedPublicKey.expanded
      )
    case .standardRepresentation:
      do {
        return try storage.withBorrowedBytes { bytes throws(SecretMemoryError) in
          try SecretBytes(copying: bytes)
        }
      } catch {
        throw .secretMemory(error)
      }
    }
  }

  package borrowing func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    randomizer: borrowing SecretBytes
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try randomizer.withBorrowedBytes { randomizerBytes throws(MLDSAError) in
      try MLDSA65Core.sign(
        message: message,
        context: context,
        privateKey: expanded,
        publicKey: encodedPublicKey.expanded,
        randomizer: randomizerBytes
      )
    }
  }

  package borrowing func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    randomizer: borrowing SecretBytes,
    into signature: inout MutableSpan<UInt8>
  ) throws(MLDSAError) {
    try randomizer.withBorrowedBytes { randomizerBytes throws(MLDSAError) in
      try MLDSA65Core.sign(
        message: message,
        context: context,
        privateKey: expanded,
        publicKey: encodedPublicKey.expanded,
        randomizer: randomizerBytes,
        into: &signature
      )
    }
  }

  package borrowing func sign(
    message: Span<UInt8>,
    context: Span<UInt8>,
    randomizer: Span<UInt8>
  ) throws(MLDSAError) -> ContiguousArray<UInt8> {
    try MLDSA65Core.sign(
      message: message,
      context: context,
      privateKey: expanded,
      publicKey: encodedPublicKey.expanded,
      randomizer: randomizer
    )
  }
}
