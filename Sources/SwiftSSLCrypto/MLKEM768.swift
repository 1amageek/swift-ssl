import SwiftSSLCore

/// FIPS 203 ML-KEM-768, the default parameter set recommended by NIST.
public enum MLKEM768: InPlaceEncodedPublicKeyEncapsulationMechanism {
  public static let encapsulationByteCount = Encapsulation.byteCount
  public static let sharedSecretByteCount = SharedSecret.byteCount
  public static let publicKeyByteCount = PublicKey.byteCount

  public struct PublicKey: Sendable, Equatable {
    public static let byteCount = 1_184
    private let storage: OwnedBytes
    fileprivate let expanded: MLKEMExpandedPublicKey

    public init(bytes: Span<UInt8>) throws(KEMError) {
      try MLKEMCore.validateEncapsulationKey(bytes, parameters: .mlKEM768)
      storage = OwnedBytes(copying: bytes)
      expanded = try MLKEMCore.expandEncapsulationKey(bytes, parameters: .mlKEM768)
    }

    fileprivate init(
      consuming bytes: consuming ContiguousArray<UInt8>,
      expanded: consuming MLKEMExpandedPublicKey
    ) {
      storage = OwnedBytes(consuming: bytes)
      self.expanded = expanded
    }

    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.storage == rhs.storage }

    public var span: Span<UInt8> { storage.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try body(storage.span)
    }
  }

  public struct PrivateKey: ~Copyable, Sendable {
    public static let byteCount = 2_400
    private let storage: SecretBytes
    fileprivate let expanded: MLKEMExpandedPrivateKey

    public init(bytes: Span<UInt8>) throws(KEMError) {
      try MLKEMCore.validateDecapsulationKey(bytes, parameters: .mlKEM768)
      let publicKeyStart = MLKEMParameters.mlKEM768.pkePrivateKeyByteCount
      let publicKeyEnd = publicKeyStart + MLKEMParameters.mlKEM768.encapsulationKeyByteCount
      let encodedPublicKey = bytes.extracting(publicKeyStart..<publicKeyEnd)
      let publicKeyHash = bytes.extracting(publicKeyEnd..<(publicKeyEnd + 32))
      let expandedPublicKey = MLKEMCore.expandEncapsulationKey(
        encodedPublicKey,
        publicKeyHash: publicKeyHash,
        parameters: .mlKEM768
      )
      let expanded = try MLKEMExpandedPrivateKey(
        decapsulationKey: bytes,
        publicKey: expandedPublicKey,
        parameters: .mlKEM768
      )
      let storage = try Self.makeStorage(copying: bytes)
      self.expanded = expanded
      self.storage = storage
    }

    fileprivate init(
      storage: consuming SecretBytes,
      expanded: MLKEMExpandedPrivateKey
    ) {
      self.expanded = expanded
      self.storage = storage
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try storage.withBorrowedBytes(body)
    }

    private static func makeStorage(
      copying bytes: Span<UInt8>
    ) throws(KEMError) -> SecretBytes {
      do {
        return try SecretBytes(copying: bytes)
      } catch {
        throw .secretMemory(error)
      }
    }
  }

  public struct Encapsulation: Sendable, Equatable {
    public static let byteCount = 1_088
    private let storage: OwnedBytes

    public init(bytes: Span<UInt8>) throws(KEMError) {
      guard bytes.count == Self.byteCount else {
        throw .invalidEncapsulationLength(expected: Self.byteCount, actual: bytes.count)
      }
      storage = OwnedBytes(copying: bytes)
    }

    fileprivate init(consuming bytes: consuming ContiguousArray<UInt8>) {
      storage = OwnedBytes(consuming: bytes)
    }

    public var span: Span<UInt8> { storage.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try body(storage.span)
    }
  }

  public struct SharedSecret: ~Copyable, Sendable {
    public static let byteCount = 32
    private let storage: SecretBytes

    fileprivate init(storage: consuming SecretBytes) {
      self.storage = storage
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
      _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
      try storage.withBorrowedBytes(body)
    }
  }

  public static func generateKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
    let seeds = try MLKEMSecretFactory.random32ByteBlocks(count: 2, using: entropy)
    return try seeds.withBorrowedBytes { bytes throws(KEMError) in
      try keyPair(
        d: bytes.extracting(0..<32),
        z: bytes.extracting(32..<64)
      )
    }
  }

  public static func generateKeyPair() throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
    try generateKeyPair(using: SystemEntropySource())
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
    try MLKEMSecretFactory.withRandom32ByteBlock(using: copy entropy) {
      bytes throws(KEMError) in
      try encapsulate(to: publicKey, message: bytes)
    }
  }

  public static func encapsulate(
    toEncodedPublicKey publicKey: Span<UInt8>,
    using entropy: borrowing any EntropySource,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    guard encapsulation.count == Encapsulation.byteCount else {
      throw .invalidEncapsulationLength(
        expected: Encapsulation.byteCount,
        actual: encapsulation.count
      )
    }
    guard sharedSecret.count == SharedSecret.byteCount else {
      throw .invalidSharedSecretLength(
        expected: SharedSecret.byteCount,
        actual: sharedSecret.count
      )
    }
    try MLKEMCore.validateEncapsulationKey(publicKey, parameters: .mlKEM768)
    let expanded = try MLKEMCore.expandEncapsulationKey(
      publicKey,
      parameters: .mlKEM768
    )
    try MLKEMSecretFactory.withRandom32ByteBlock(using: copy entropy) {
      message throws(KEMError) in
      try MLKEMCore.encapsulate(
        parameters: .mlKEM768,
        expandedPublicKey: expanded,
        message: message,
        ciphertext: &encapsulation,
        sharedSecret: &sharedSecret
      )
    }
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
    try encapsulate(to: publicKey, using: SystemEntropySource())
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    guard encapsulation.count == Encapsulation.byteCount else {
      throw .invalidEncapsulationLength(
        expected: Encapsulation.byteCount,
        actual: encapsulation.count
      )
    }
    guard sharedSecret.count == SharedSecret.byteCount else {
      throw .invalidSharedSecretLength(
        expected: SharedSecret.byteCount,
        actual: sharedSecret.count
      )
    }
    try MLKEMSecretFactory.withRandom32ByteBlock(using: copy entropy) {
      bytes throws(KEMError) in
      try encapsulate(
        to: publicKey,
        message: bytes,
        into: &encapsulation,
        sharedSecret: &sharedSecret
      )
    }
  }

  public static func encapsulate(
    to publicKey: borrowing PublicKey,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    try encapsulate(
      to: publicKey,
      using: SystemEntropySource(),
      into: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  public static func decapsulate(
    _ encapsulation: borrowing Encapsulation,
    using privateKey: borrowing PrivateKey
  ) throws(KEMError) -> SharedSecret {
    let storage = try MLKEMSecretFactory.make(byteCount: SharedSecret.byteCount) {
      output throws(KEMError) in
      try MLKEMCore.decapsulate(
        parameters: .mlKEM768,
        expandedPrivateKey: privateKey.expanded,
        ciphertext: encapsulation.span,
        sharedSecret: &output
      )
    }
    return SharedSecret(storage: storage)
  }

  public static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing PrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    guard encapsulation.count == Encapsulation.byteCount else {
      throw .invalidEncapsulationLength(
        expected: Encapsulation.byteCount,
        actual: encapsulation.count
      )
    }
    guard sharedSecret.count == SharedSecret.byteCount else {
      throw .invalidSharedSecretLength(
        expected: SharedSecret.byteCount,
        actual: sharedSecret.count
      )
    }
    try MLKEMCore.decapsulate(
      parameters: .mlKEM768,
      expandedPrivateKey: privateKey.expanded,
      ciphertext: encapsulation,
      sharedSecret: &sharedSecret
    )
  }

  static func keyPair(
    d: Span<UInt8>,
    z: Span<UInt8>
  ) throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
    guard d.count == 32 else {
      throw .invalidPrivateKeyLength(expected: 32, actual: d.count)
    }
    guard z.count == 32 else {
      throw .invalidPrivateKeyLength(expected: 32, actual: z.count)
    }
    var publicBytes = ContiguousArray<UInt8>(
      repeating: 0,
      count: PublicKey.byteCount
    )
    var expandedPublicKey: MLKEMExpandedPublicKey?
    var expandedPrivateKey: MLKEMExpandedPrivateKey?
    let privateStorage = try MLKEMSecretFactory.make(byteCount: PrivateKey.byteCount) {
      privateOutput throws(KEMError) in
      var publicOutput = publicBytes.mutableSpan
      let generated = try MLKEMCore.keyGenerate(
        parameters: .mlKEM768,
        d: d,
        z: z,
        encapsulationKey: &publicOutput,
        decapsulationKey: &privateOutput
      )
      expandedPublicKey = generated.publicKey
      expandedPrivateKey = generated.privateKey
    }
    guard let expandedPublicKey, let expandedPrivateKey else {
      preconditionFailure(
        "successful ML-KEM key generation must produce expanded key material")
    }
    let privateKey = PrivateKey(
      storage: privateStorage,
      expanded: expandedPrivateKey
    )
    return KEMKeyPair(
      publicKey: PublicKey(consuming: publicBytes, expanded: expandedPublicKey),
      privateKey: privateKey
    )
  }

  static func encapsulate(
    to publicKey: borrowing PublicKey,
    message: Span<UInt8>
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
    guard message.count == 32 else {
      throw .invalidEncapsulationLength(expected: 32, actual: message.count)
    }
    var ciphertextBytes = ContiguousArray<UInt8>(
      repeating: 0,
      count: Encapsulation.byteCount
    )
    let secretStorage = try MLKEMSecretFactory.make(byteCount: SharedSecret.byteCount) {
      secretOutput throws(KEMError) in
      var ciphertextOutput = ciphertextBytes.mutableSpan
      try encapsulate(
        to: publicKey,
        message: message,
        into: &ciphertextOutput,
        sharedSecret: &secretOutput
      )
    }
    return EncapsulationResult(
      encapsulation: Encapsulation(consuming: ciphertextBytes),
      sharedSecret: SharedSecret(storage: secretStorage)
    )
  }

  static func encapsulate(
    to publicKey: borrowing PublicKey,
    message: Span<UInt8>,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    guard message.count == 32 else {
      throw .invalidEncapsulationLength(expected: 32, actual: message.count)
    }
    guard encapsulation.count == Encapsulation.byteCount else {
      throw .invalidEncapsulationLength(
        expected: Encapsulation.byteCount,
        actual: encapsulation.count
      )
    }
    guard sharedSecret.count == SharedSecret.byteCount else {
      throw .invalidSharedSecretLength(
        expected: SharedSecret.byteCount,
        actual: sharedSecret.count
      )
    }
    try MLKEMCore.encapsulate(
      parameters: .mlKEM768,
      expandedPublicKey: publicKey.expanded,
      message: message,
      ciphertext: &encapsulation,
      sharedSecret: &sharedSecret
    )
  }
}
