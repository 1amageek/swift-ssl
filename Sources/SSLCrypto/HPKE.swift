import SSLCore

/// HKDF choices for the X25519 HPKE profile.
public enum HPKEKDF: Sendable, Hashable {
  case sha256
  case sha384
  case sha512

  public var digestByteCount: Int {
    switch self {
    case .sha256: return SHA256.digestByteCount
    case .sha384: return SHA384.digestByteCount
    case .sha512: return SHA512.digestByteCount
    }
  }

  fileprivate var identifier: UInt16 {
    switch self {
    case .sha256: return 0x0001
    case .sha384: return 0x0002
    case .sha512: return 0x0003
    }
  }
}

/// AEAD choices for HPKE. Every choice uses a 96-bit nonce and a 128-bit tag.
public enum HPKEAEAD: Sendable, Hashable {
  case aes128GCM
  case aes256GCM
  case chaCha20Poly1305

  public var keyByteCount: Int {
    switch self {
    case .aes128GCM: return 16
    case .aes256GCM: return 32
    case .chaCha20Poly1305: return 32
    }
  }

  public static let nonceByteCount = 12
  public static let tagByteCount = 16

  fileprivate var identifier: UInt16 {
    switch self {
    case .aes128GCM: return 0x0001
    case .aes256GCM: return 0x0002
    case .chaCha20Poly1305: return 0x0003
    }
  }
}

public enum HPKEMode: Sendable, Hashable {
  case base
  case psk
  case auth
  case authPSK

  fileprivate var encoded: UInt8 {
    switch self {
    case .base: return 0x00
    case .psk: return 0x01
    case .auth: return 0x02
    case .authPSK: return 0x03
    }
  }
}

public enum HPKEError: Error, Sendable, Equatable {
  case invalidConfiguration
  case invalidEncapsulation
  case invalidPseudorandomKey
  case sequenceExhausted
  case exporterLengthOutOfRange(Int)
  case keyGeneration(X25519KeyGenerationError)
  case p256KeyGeneration(P256KeyGenerationError)
  case keyDerivation(HKDFError)
  case secretMemory(SecretMemoryError)
  case primitive(CryptoInputError)
  case authenticatedCipher(AEADError)
}

/// Secret exporter output owned by an HPKE context.
///
/// The bytes can only be observed through a scoped borrow. Deinitialization
/// wipes the allocation; an empty export exposes zero bytes through a wiped
/// one-byte sentinel so the owner remains structurally noncopyable.
public struct HPKEExportedSecret: ~Copyable, Sendable {
  private let storage: SecretBytes
  private let exportedCount: Int

  fileprivate init(consuming bytes: consuming ContiguousArray<UInt8>) throws(HPKEError) {
    var bytes = bytes
    exportedCount = bytes.count
    if bytes.isEmpty { bytes.append(0) }
    defer { HPKEPrimitives.wipe(&bytes) }
    do {
      storage = try SecretBytes(copying: bytes.span)
    } catch let error {
      throw .secretMemory(error)
    }
  }

  public var count: Int { exportedCount }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try storage.withBorrowedBytes { (bytes: Span<UInt8>) throws(Failure) -> Result in
      try body(bytes.extracting(0..<exportedCount))
    }
  }
}

/// The sender side of one X25519/HKDF/AEAD HPKE context.
///
/// The context owns all secret state and consumes one sequence number after
/// each successful seal. The nonce is derived as `base_nonce XOR I2OSP(seq)`;
/// the sequence is deliberately bounded to `UInt64` so overflow is a typed
/// failure rather than a silent nonce reuse.
public struct HPKESenderContext: ~Copyable, Sendable {
  private let secretState: SecretBytes
  private let cipher: HPKEAEADContext
  private let kdf: HPKEKDF
  private let aead: HPKEAEAD
  private let kemIdentifier: UInt16
  private var sequence: UInt64

  init(material: consuming HPKEContextMaterial) {
    kdf = material.kdf
    aead = material.aead
    kemIdentifier = material.kemIdentifier
    cipher = consume material.cipher
    secretState = consume material.secretState
    sequence = 0
  }

  public var sequenceNumber: UInt64 { sequence }

  public mutating func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(HPKEError) -> OwnedBytes {
    let (required, overflow) = plaintext.count.addingReportingOverflow(
      HPKEAEAD.tagByteCount
    )
    guard !overflow else { throw .authenticatedCipher(.messageLimitReached) }
    var output = ContiguousArray<UInt8>(repeating: 0, count: required)
    var destination = output.mutableSpan
    try seal(
      plaintext: plaintext,
      authenticatedData: authenticatedData,
      into: &destination
    )
    return OwnedBytes(consuming: output)
  }

  /// Seals directly into caller-owned contiguous storage.
  ///
  /// The destination must have exactly `plaintext.count + 16` bytes. Inputs
  /// may not overlap the destination because authenticated data must remain
  /// immutable until the AEAD operation completes.
  public mutating func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    guard sequence < UInt64.max else { throw .sequenceExhausted }
    let (required, overflow) = plaintext.count.addingReportingOverflow(
      HPKEAEAD.tagByteCount
    )
    guard !overflow else { throw .authenticatedCipher(.messageLimitReached) }
    guard output.count == required else {
      throw .authenticatedCipher(
        .outputTooSmall(required: required, actual: output.count)
      )
    }
    try withNonce { nonce throws(HPKEError) in
      try cipher.seal(
        plaintext: plaintext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &output
      )
    }
    sequence += 1
  }

  public borrowing func export(
    _ exporterContext: Span<UInt8>,
    length: Int
  ) throws(HPKEError) -> HPKEExportedSecret {
    guard length >= 0 else { throw .exporterLengthOutOfRange(length) }
    return try secretState.withBorrowedBytes { state throws(HPKEError) in
      let offset = HPKEAEAD.nonceByteCount
      let secret = state.extracting(offset..<state.count)
      let value = try HPKEPrimitives.export(
        secret: secret,
        exporterContext: exporterContext,
        length: length,
        kdf: kdf,
        aead: aead,
        kemIdentifier: kemIdentifier
      )
      return try HPKEExportedSecret(consuming: value)
    }
  }

  private borrowing func withNonce<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try secretState.withBorrowedBytes { state throws(Failure) in
      // Unsafe boundary invariants:
      // - The temporary allocation has exactly 12 initialized UInt8 values.
      // - The immutable key and base nonce remain borrowed from secretState.
      // - The nonce pointer and both spans are confined to this synchronous closure.
      // - All offsets are bounded by the validated packed-state layout.
      // - No aliasing mutation or Sendable boundary exists during the borrow.
      try withUnsafeTemporaryAllocation(
        of: UInt8.self,
        capacity: HPKEAEAD.nonceByteCount
      ) { nonceBuffer throws(Failure) -> Result in
        let baseNonce = state.extracting(0..<HPKEAEAD.nonceByteCount)
        var index = 0
        while index < HPKEAEAD.nonceByteCount {
          nonceBuffer[index] = baseNonce[index]
          index += 1
        }
        index = 0
        while index < MemoryLayout<UInt64>.size {
          nonceBuffer[HPKEAEAD.nonceByteCount - 1 - index] ^=
            UInt8(truncatingIfNeeded: sequence >> UInt64(index * 8))
          index += 1
        }
        let nonce = Span(
          _unsafeElements: UnsafeBufferPointer(
            start: nonceBuffer.baseAddress,
            count: HPKEAEAD.nonceByteCount
          )
        )
        return try body(nonce)
      }
    }
  }
}

/// The recipient side of one X25519/HKDF/AEAD HPKE context.
public struct HPKERecipientContext: ~Copyable, Sendable {
  private let secretState: SecretBytes
  private let cipher: HPKEAEADContext
  private let kdf: HPKEKDF
  private let aead: HPKEAEAD
  private let kemIdentifier: UInt16
  private var sequence: UInt64

  init(material: consuming HPKEContextMaterial) {
    kdf = material.kdf
    aead = material.aead
    kemIdentifier = material.kemIdentifier
    cipher = consume material.cipher
    secretState = consume material.secretState
    sequence = 0
  }

  public var sequenceNumber: UInt64 { sequence }

  public mutating func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(HPKEError) -> OwnedBytes {
    guard ciphertext.count >= HPKEAEAD.tagByteCount else {
      throw .authenticatedCipher(
        .outputTooSmall(
          required: HPKEAEAD.tagByteCount,
          actual: ciphertext.count
        )
      )
    }
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: ciphertext.count - HPKEAEAD.tagByteCount
    )
    var destination = output.mutableSpan
    try open(
      ciphertext: ciphertext,
      authenticatedData: authenticatedData,
      into: &destination
    )
    return OwnedBytes(consuming: output)
  }

  /// Opens directly into caller-owned contiguous storage.
  ///
  /// The destination must have exactly `ciphertext.count - 16` bytes. A
  /// failed authentication does not advance the context sequence.
  public mutating func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    guard sequence < UInt64.max else { throw .sequenceExhausted }
    guard ciphertext.count >= HPKEAEAD.tagByteCount else {
      throw .authenticatedCipher(
        .outputTooSmall(
          required: HPKEAEAD.tagByteCount,
          actual: ciphertext.count
        )
      )
    }
    let required = ciphertext.count - HPKEAEAD.tagByteCount
    guard output.count == required else {
      throw .authenticatedCipher(
        .outputTooSmall(required: required, actual: output.count)
      )
    }
    try withNonce { nonce throws(HPKEError) in
      try cipher.open(
        ciphertext: ciphertext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &output
      )
    }
    sequence += 1
  }

  public borrowing func export(
    _ exporterContext: Span<UInt8>,
    length: Int
  ) throws(HPKEError) -> HPKEExportedSecret {
    guard length >= 0 else { throw .exporterLengthOutOfRange(length) }
    return try secretState.withBorrowedBytes { state throws(HPKEError) in
      let offset = HPKEAEAD.nonceByteCount
      let secret = state.extracting(offset..<state.count)
      let value = try HPKEPrimitives.export(
        secret: secret,
        exporterContext: exporterContext,
        length: length,
        kdf: kdf,
        aead: aead,
        kemIdentifier: kemIdentifier
      )
      return try HPKEExportedSecret(consuming: value)
    }
  }

  private borrowing func withNonce<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try secretState.withBorrowedBytes { state throws(Failure) in
      // Unsafe boundary invariants:
      // - The temporary allocation has exactly 12 initialized UInt8 values.
      // - The immutable key and base nonce remain borrowed from secretState.
      // - The nonce pointer and both spans are confined to this synchronous closure.
      // - All offsets are bounded by the validated packed-state layout.
      // - No aliasing mutation or Sendable boundary exists during the borrow.
      try withUnsafeTemporaryAllocation(
        of: UInt8.self,
        capacity: HPKEAEAD.nonceByteCount
      ) { nonceBuffer throws(Failure) -> Result in
        let baseNonce = state.extracting(0..<HPKEAEAD.nonceByteCount)
        var index = 0
        while index < HPKEAEAD.nonceByteCount {
          nonceBuffer[index] = baseNonce[index]
          index += 1
        }
        index = 0
        while index < MemoryLayout<UInt64>.size {
          nonceBuffer[HPKEAEAD.nonceByteCount - 1 - index] ^=
            UInt8(truncatingIfNeeded: sequence >> UInt64(index * 8))
          index += 1
        }
        let nonce = Span(
          _unsafeElements: UnsafeBufferPointer(
            start: nonceBuffer.baseAddress,
            count: HPKEAEAD.nonceByteCount
          )
        )
        return try body(nonce)
      }
    }
  }
}

public struct HPKESenderSetup: ~Copyable, Sendable {
  public let encapsulation: OwnedBytes
  public let context: HPKESenderContext

  init(
    encapsulation: consuming OwnedBytes,
    context: consuming HPKESenderContext
  ) {
    self.encapsulation = encapsulation
    self.context = context
  }

  /// Moves the sender context out after the encapsulation has been consumed
  /// by the recipient setup. The setup value itself remains noncopyable.
  public consuming func takeContext() -> HPKESenderContext {
    consume context
  }
}

/// RFC 9180 X25519 DHKEM with the complete Base, PSK, Auth, and AuthPSK
/// setup modes. P-256/P-384/P-521 DHKEM and X448 are separate profiles and do
/// not silently fall back to this KEM identifier.
public enum HPKEX25519 {
  public static let kemIdentifier: UInt16 = 0x0020

  public static func setupBaseSender(
    recipientPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeSender(
      mode: .base,
      recipientPublicKey: recipientPublicKey,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead,
      using: entropy
    )
  }

  public static func setupPSKSender(
    recipientPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeSender(
      mode: .psk,
      recipientPublicKey: recipientPublicKey,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead,
      using: entropy
    )
  }

  public static func setupAuthSender(
    recipientPublicKey: borrowing X25519PublicKey,
    senderKeyPair: borrowing X25519KeyPair,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeAuthSender(
      mode: .auth,
      recipientPublicKey: recipientPublicKey,
      senderKeyPair: senderKeyPair,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead,
      using: entropy
    )
  }

  public static func setupAuthPSKSender(
    recipientPublicKey: borrowing X25519PublicKey,
    senderKeyPair: borrowing X25519KeyPair,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeAuthSender(
      mode: .authPSK,
      recipientPublicKey: recipientPublicKey,
      senderKeyPair: senderKeyPair,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead,
      using: entropy
    )
  }

  public static func setupBaseRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing X25519KeyPair,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeRecipient(
      mode: .base,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: nil,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupPSKRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing X25519KeyPair,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeRecipient(
      mode: .psk,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: nil,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupAuthRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing X25519KeyPair,
    senderPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    let sender = senderPublicKey.withBorrowedBytes { copy($0) }
    return try makeRecipient(
      mode: .auth,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: sender,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupAuthPSKRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing X25519KeyPair,
    senderPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    let sender = senderPublicKey.withBorrowedBytes { copy($0) }
    return try makeRecipient(
      mode: .authPSK,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: sender,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
  }

  private static func makeSender(
    mode: HPKEMode,
    recipientPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try HPKEPrimitives.validate(mode: mode, psk: psk, pskID: pskID)
    guard mode == .base || mode == .psk else {
      throw .invalidConfiguration
    }
    let ephemeral: X25519PrivateKey
    do {
      ephemeral = try X25519PrivateKey.generate(using: entropy)
    } catch let error {
      throw .keyGeneration(error)
    }
    let encapsulation = ephemeral.publicKey()
    let enc = OwnedBytes(copying: encapsulation.span)
    let material = try withSharedSecret(
      privateKey: ephemeral,
      peerPublicKey: recipientPublicKey
    ) { dh throws(HPKEError) -> HPKEContextMaterial in
      try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation.span,
        recipientPublicKey: recipientPublicKey.span,
        senderPublicKey: nil,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
    }
    let context = HPKESenderContext(material: consume material)
    return HPKESenderSetup(
      encapsulation: consume enc,
      context: consume context
    )
  }

  private static func makeAuthSender(
    mode: HPKEMode,
    recipientPublicKey: borrowing X25519PublicKey,
    senderKeyPair: borrowing X25519KeyPair,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try HPKEPrimitives.validate(mode: mode, psk: psk, pskID: pskID)
    guard mode == .auth || mode == .authPSK else {
      throw .invalidConfiguration
    }
    let ephemeral: X25519PrivateKey
    do {
      ephemeral = try X25519PrivateKey.generate(using: entropy)
    } catch let error {
      throw .keyGeneration(error)
    }
    let encapsulation = ephemeral.publicKey()
    let enc = OwnedBytes(copying: encapsulation.span)
    let senderPublic = copy(senderKeyPair.publicKey.span)
    let material = try withAuthenticatedSharedSecrets(
      firstPrivateKey: ephemeral,
      firstPeerPublicKeyBytes: recipientPublicKey.span,
      secondPrivateKey: senderKeyPair.privateKey,
      secondPeerPublicKeyBytes: recipientPublicKey.span
    ) { dh throws(HPKEError) -> HPKEContextMaterial in
      try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation.span,
        recipientPublicKey: recipientPublicKey.span,
        senderPublicKey: senderPublic,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
    }
    let context = HPKESenderContext(material: consume material)
    return HPKESenderSetup(
      encapsulation: consume enc,
      context: consume context
    )
  }

  private static func makeRecipient(
    mode: HPKEMode,
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing X25519KeyPair,
    senderPublicKey: ContiguousArray<UInt8>?,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try HPKEPrimitives.validate(mode: mode, psk: psk, pskID: pskID)
    guard encapsulation.count == X25519PublicKey.byteCount else {
      throw .invalidEncapsulation
    }
    guard (mode == .base || mode == .psk) || senderPublicKey != nil else {
      throw .invalidConfiguration
    }
    if let senderPublicKey {
      let sender: X25519PublicKey
      do { sender = try X25519PublicKey(bytes: senderPublicKey.span) } catch {
        throw .invalidConfiguration
      }
      return try withAuthenticatedSharedSecrets(
        firstPrivateKey: recipientKeyPair.privateKey,
        firstPeerPublicKeyBytes: encapsulation,
        secondPrivateKey: recipientKeyPair.privateKey,
        secondPeerPublicKeyBytes: sender.span
      ) { dh throws(HPKEError) -> HPKERecipientContext in
        let material = try finishSender(
          mode: mode,
          dh: dh,
          encapsulation: encapsulation,
          recipientPublicKey: recipientKeyPair.publicKey.span,
          senderPublicKey: senderPublicKey,
          info: info,
          psk: psk,
          pskID: pskID,
          kdf: kdf,
          aead: aead
        )
        return HPKERecipientContext(material: consume material)
      }
    }
    return try withSharedSecret(
      privateKey: recipientKeyPair.privateKey,
      peerPublicKeyBytes: encapsulation
    ) { dh throws(HPKEError) -> HPKERecipientContext in
      let material = try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation,
        recipientPublicKey: recipientKeyPair.publicKey.span,
        senderPublicKey: nil,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
      return HPKERecipientContext(material: consume material)
    }
  }

  private static func finishSender(
    mode: HPKEMode,
    dh: Span<UInt8>,
    encapsulation: Span<UInt8>,
    recipientPublicKey: Span<UInt8>,
    senderPublicKey: ContiguousArray<UInt8>?,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    return try HPKEPrimitives.withKEMSharedSecret(
      kemIdentifier: kemIdentifier,
      dh: dh,
      encapsulation: encapsulation,
      recipientPublicKey: recipientPublicKey,
      senderPublicKey: senderPublicKey
    ) {
      sharedSecret,
      preparedEmptyInnerContext,
      preparedEmptyOuterContext throws(HPKEError) -> HPKEContextMaterial in
      try HPKEPrimitives.deriveContext(
        kemIdentifier: kemIdentifier,
        sharedSecret: sharedSecret,
        preparedEmptyInnerContext: preparedEmptyInnerContext,
        preparedEmptyOuterContext: preparedEmptyOuterContext,
        mode: mode,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
    }
  }

  private static let emptyBytes = ContiguousArray<UInt8>()

  private static func copy(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
      result.append(bytes[index])
      index += 1
    }
    return result
  }

  private static func withSharedSecret<Result: ~Copyable>(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    try withSharedSecret(
      privateKey: privateKey,
      peerPublicKeyBytes: peerPublicKey.span,
      body
    )
  }

  private static func withSharedSecret<Result: ~Copyable>(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD value owns exactly 32 initialized inline bytes; it has no
    //   separately allocated storage and its complete contents are wiped once
    //   before this scope exits.
    // - Every pointer and Span remains inside its withUnsafeBytes closure and
    //   cannot outlive the SIMD owner or cross a Sendable boundary.
    // - X25519.sharedSecretByteCount is exactly 32, so every offset and count
    //   is in bounds without integer overflow. UInt8 has stride/alignment one.
    // - Raw storage is explicitly bound to UInt8. The mutable borrow is
    //   exclusive, and the later immutable borrow starts only after it ends.
    var shared = SIMD32<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) {
        rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        var destination = MutableSpan(
          _unsafeStart: bytes.baseAddress.unsafelyUnwrapped,
          count: X25519.sharedSecretByteCount
        )
        try X25519.sharedSecret(
          privateKey: privateKey,
          peerPublicKeyBytes: peerPublicKeyBytes,
          into: &destination
        )
      }
    } catch let error {
      throw .primitive(error)
    }
    return try withUnsafeBytes(of: &shared) {
      rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
    }
  }

  private static func withAuthenticatedSharedSecrets<Result: ~Copyable>(
    firstPrivateKey: borrowing X25519PrivateKey,
    firstPeerPublicKeyBytes: Span<UInt8>,
    secondPrivateKey: borrowing X25519PrivateKey,
    secondPeerPublicKeyBytes: Span<UInt8>,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD value owns exactly 64 initialized inline bytes containing two
    //   adjacent 32-byte X25519 results and is wiped once before scope exit.
    // - Both MutableSpan values remain in the exclusive raw-memory closure;
    //   the combined immutable Span is borrowed only by the synchronous body.
    // - The second offset is the fixed first 32-byte extent, the combined
    //   count is exactly 64, and UInt8 has stride/alignment one.
    // - Storage is explicitly bound to UInt8 with no rebind or overlapping
    //   mutable alias. No pointer or borrow crosses a Sendable boundary.
    var shared = SIMD64<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) {
        rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        let pointer = bytes.baseAddress.unsafelyUnwrapped
        var firstDestination = MutableSpan(
          _unsafeStart: pointer,
          count: X25519.sharedSecretByteCount
        )
        try X25519.sharedSecret(
          privateKey: firstPrivateKey,
          peerPublicKeyBytes: firstPeerPublicKeyBytes,
          into: &firstDestination
        )
        var secondDestination = MutableSpan(
          _unsafeStart: pointer.advanced(by: X25519.sharedSecretByteCount),
          count: X25519.sharedSecretByteCount
        )
        try X25519.sharedSecret(
          privateKey: secondPrivateKey,
          peerPublicKeyBytes: secondPeerPublicKeyBytes,
          into: &secondDestination
        )
      }
    } catch let error {
      throw .primitive(error)
    }
    return try withUnsafeBytes(of: &shared) {
      rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
    }
  }

  private static func append(
    _ destination: inout ContiguousArray<UInt8>,
    _ source: Span<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  fileprivate static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }
}

struct HPKEContextMaterial: ~Copyable, Sendable {
  let secretState: SecretBytes
  let cipher: HPKEAEADContext
  let kdf: HPKEKDF
  let aead: HPKEAEAD
  let kemIdentifier: UInt16
}

enum HPKEPrimitives {
  private static let version = ContiguousArray<UInt8>([0x48, 0x50, 0x4B, 0x45, 0x2D, 0x76, 0x31])

  static func validate(
    mode: HPKEMode,
    psk: Span<UInt8>,
    pskID: Span<UInt8>
  ) throws(HPKEError) {
    switch mode {
    case .base, .auth:
      guard psk.isEmpty, pskID.isEmpty else { throw .invalidPseudorandomKey }
    case .psk, .authPSK:
      guard !psk.isEmpty, !pskID.isEmpty else { throw .invalidPseudorandomKey }
    }
  }

  static func withKEMSharedSecret<Result: ~Copyable>(
    kemIdentifier: UInt16,
    dh: Span<UInt8>,
    encapsulation: Span<UInt8>,
    recipientPublicKey: Span<UInt8>,
    senderPublicKey: ContiguousArray<UInt8>?,
    _ body: (
      Span<UInt8>,
      borrowing SHA256Context,
      borrowing SHA256Context
    ) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    let kemSuiteID = kemSuiteID(for: kemIdentifier)
    var eaePRK = SIMD32<UInt8>(repeating: 0)
    var sharedSecret = SIMD32<UInt8>(repeating: 0)
    var preparedEmptyInnerContext = SHA256Context()
    var preparedEmptyOuterContext = SHA256Context()
    defer {
      wipe(&eaePRK)
      wipe(&sharedSecret)
      preparedEmptyInnerContext.eraseSensitiveState()
      preparedEmptyOuterContext.eraseSensitiveState()
    }
    do {
      try HMACSHA256Core.initializeFreshContexts(
        authenticatingWith: emptyBytes.span,
        innerContext: &preparedEmptyInnerContext,
        outerContext: &preparedEmptyOuterContext
      )
      try withUnsafeMutableBytes(of: &eaePRK) {
        bytes throws(CryptoInputError) in
        let pointer = bytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        var output = MutableSpan(
          _unsafeStart: pointer,
          count: SHA256.digestByteCount
        )
        try HPKESHA256LabeledKDF.extract(
          preparedInnerContext: preparedEmptyInnerContext,
          preparedOuterContext: preparedEmptyOuterContext,
          suiteID: kemSuiteID.span,
          label: "eae_prk",
          input: dh,
          into: &output
        )
      }
      try withUnsafeBytes(of: &eaePRK) {
        prkBytes throws(CryptoInputError) in
        let prkPointer = prkBytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        let prk = Span(
          _unsafeElements: UnsafeBufferPointer(
            start: prkPointer,
            count: SHA256.digestByteCount
          )
        )
        try withUnsafeMutableBytes(of: &sharedSecret) {
          outputBytes throws(CryptoInputError) in
          let outputPointer = outputBytes.baseAddress.unsafelyUnwrapped
            .assumingMemoryBound(to: UInt8.self)
          var output = MutableSpan(
            _unsafeStart: outputPointer,
            count: SHA256.digestByteCount
          )
          try HPKESHA256LabeledKDF.expand(
            pseudorandomKey: prk,
            suiteID: kemSuiteID.span,
            label: "shared_secret",
            outputByteCount: SHA256.digestByteCount,
            updateInfo: { context throws(CryptoInputError) in
              try context.update(encapsulation)
              try context.update(recipientPublicKey)
              if let senderPublicKey {
                try context.update(senderPublicKey.span)
              }
            },
            into: &output
          )
        }
      }
    } catch {
      throw .primitive(error)
    }
    return try withUnsafeBytes(of: &sharedSecret) {
      bytes throws(HPKEError) -> Result in
      let pointer = bytes.baseAddress.unsafelyUnwrapped
        .assumingMemoryBound(to: UInt8.self)
      let shared = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: pointer,
          count: SHA256.digestByteCount
        )
      )
      return try body(
        shared,
        preparedEmptyInnerContext,
        preparedEmptyOuterContext
      )
    }
  }

  static func deriveContext(
    kemIdentifier: UInt16,
    sharedSecret: Span<UInt8>,
    preparedEmptyInnerContext: borrowing SHA256Context,
    preparedEmptyOuterContext: borrowing SHA256Context,
    mode: HPKEMode,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    if kdf == .sha256 {
      return try deriveSHA256Context(
        kemIdentifier: kemIdentifier,
        sharedSecret: sharedSecret,
        preparedEmptyInnerContext: preparedEmptyInnerContext,
        preparedEmptyOuterContext: preparedEmptyOuterContext,
        mode: mode,
        info: info,
        psk: psk,
        pskID: pskID,
        aead: aead
      )
    }
    let suiteID = hpkeSuiteID(kemIdentifier: kemIdentifier, kdf: kdf, aead: aead)
    var pskIDHash = try labeledExtract(
      salt: emptyBytes.span,
      label: "psk_id_hash",
      input: pskID,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&pskIDHash) }
    var infoHash = try labeledExtract(
      salt: emptyBytes.span,
      label: "info_hash",
      input: info,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&infoHash) }
    var context = ContiguousArray<UInt8>(repeating: 0, count: 1)
    context[0] = mode.encoded
    append(&context, pskIDHash.span)
    append(&context, infoHash.span)

    var secret = try labeledExtract(
      salt: sharedSecret,
      label: "secret",
      input: psk,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&secret) }
    var key = try labeledExpand(
      prk: secret.span,
      label: "key",
      info: context.span,
      length: aead.keyByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&key) }
    var baseNonce = try labeledExpand(
      prk: secret.span,
      label: "base_nonce",
      info: context.span,
      length: HPKEAEAD.nonceByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&baseNonce) }
    var exporterSecret = try labeledExpand(
      prk: secret.span,
      label: "exp",
      info: context.span,
      length: kdf.digestByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    defer { wipe(&exporterSecret) }
    let totalByteCount = baseNonce.count + exporterSecret.count
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(totalByteCount)
    } catch let error {
      throw .secretMemory(error)
    }
    let cipher = try HPKEAEADContext(key: key.span, algorithm: aead)
    let secretState = SecretBytes(byteCount: byteCount) { destination in
      copy(baseNonce.span, into: &destination, at: 0)
      copy(
        exporterSecret.span,
        into: &destination,
        at: baseNonce.count
      )
    }
    return HPKEContextMaterial(
      secretState: consume secretState,
      cipher: consume cipher,
      kdf: kdf,
      aead: aead,
      kemIdentifier: kemIdentifier
    )
  }

  private static func deriveSHA256Context(
    kemIdentifier: UInt16,
    sharedSecret: Span<UInt8>,
    preparedEmptyInnerContext: borrowing SHA256Context,
    preparedEmptyOuterContext: borrowing SHA256Context,
    mode: HPKEMode,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    let suiteID = hpkeSuiteID(
      kemIdentifier: kemIdentifier,
      kdf: .sha256,
      aead: aead
    )
    // Unsafe boundary invariants:
    // - These inline SIMD owners contain 64, 32, and 32 initialized bytes;
    //   every byte is wiped once before this function returns or throws.
    // - Raw storage is bound only to UInt8, whose stride/alignment is one.
    // - The key output count is selected from 16 or 32 and cannot exceed its
    //   32-byte owner; all context and digest extents are fixed and in bounds.
    // - Mutable borrows are exclusive and end before immutable borrows begin.
    //   No pointer or Span escapes a closure or crosses a Sendable boundary.
    var contextHashes = SIMD64<UInt8>(repeating: 0)
    var secret = SIMD32<UInt8>(repeating: 0)
    var key = SIMD32<UInt8>(repeating: 0)
    defer {
      wipe(&contextHashes)
      wipe(&secret)
      wipe(&key)
    }

    do {
      try withUnsafeMutableBytes(of: &contextHashes) {
        bytes throws(CryptoInputError) in
        let pointer = bytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        var pskIDHash = MutableSpan(
          _unsafeStart: pointer,
          count: SHA256.digestByteCount
        )
        try HPKESHA256LabeledKDF.extract(
          preparedInnerContext: preparedEmptyInnerContext,
          preparedOuterContext: preparedEmptyOuterContext,
          suiteID: suiteID.span,
          label: "psk_id_hash",
          input: pskID,
          into: &pskIDHash
        )
        var infoHash = MutableSpan(
          _unsafeStart: pointer.advanced(by: SHA256.digestByteCount),
          count: SHA256.digestByteCount
        )
        try HPKESHA256LabeledKDF.extract(
          preparedInnerContext: preparedEmptyInnerContext,
          preparedOuterContext: preparedEmptyOuterContext,
          suiteID: suiteID.span,
          label: "info_hash",
          input: info,
          into: &infoHash
        )
      }
      try withUnsafeMutableBytes(of: &secret) {
        bytes throws(CryptoInputError) in
        let pointer = bytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        var output = MutableSpan(
          _unsafeStart: pointer,
          count: SHA256.digestByteCount
        )
        try HPKESHA256LabeledKDF.extract(
          salt: sharedSecret,
          suiteID: suiteID.span,
          label: "secret",
          input: psk,
          into: &output
        )
      }
    } catch {
      throw .primitive(error)
    }

    let stateByteCount = HPKEAEAD.nonceByteCount + SHA256.digestByteCount
    let validatedByteCount: SecretByteCount
    do {
      validatedByteCount = try SecretByteCount(stateByteCount)
    } catch let error {
      throw .secretMemory(error)
    }

    let secretState: SecretBytes
    do {
      secretState = try withUnsafeBytes(of: &secret) {
        rawSecretBytes throws(CryptoInputError) -> SecretBytes in
        let secretSpan = Span(
          _unsafeElements: rawSecretBytes.bindMemory(to: UInt8.self)
        )
        return try HMACSHA256Core.withPreparedContexts(
          authenticatingWith: secretSpan
        ) { preparedInner, preparedOuter throws(CryptoInputError) -> SecretBytes in
          try withUnsafeBytes(of: &contextHashes) {
            rawContextBytes throws(CryptoInputError) -> SecretBytes in
            let contextSpan = Span(
              _unsafeElements: rawContextBytes.bindMemory(to: UInt8.self)
            )
            return try SecretBytes(byteCount: validatedByteCount) {
              destination throws(CryptoInputError) in
              var modeByte = mode.encoded
              try withUnsafeBytes(of: &modeByte) {
                modeBytes throws(CryptoInputError) in
                let modeSpan = Span(
                  _unsafeElements: modeBytes.bindMemory(to: UInt8.self)
                )
                try withUnsafeMutableBytes(of: &key) {
                  rawKeyBytes throws(CryptoInputError) in
                  let keyBytes = rawKeyBytes.bindMemory(to: UInt8.self)
                  var keyOutput = MutableSpan(
                    _unsafeStart: keyBytes.baseAddress.unsafelyUnwrapped,
                    count: aead.keyByteCount
                  )
                  try HPKESHA256LabeledKDF.expand(
                    preparedInnerContext: preparedInner,
                    preparedOuterContext: preparedOuter,
                    suiteID: suiteID.span,
                    label: "key",
                    outputByteCount: keyOutput.count,
                    updateInfo: { context throws(CryptoInputError) in
                      try context.update(modeSpan)
                      try context.update(contextSpan)
                    },
                    into: &keyOutput
                  )
                }
                let nonceOffset = 0
                var nonce = destination._mutatingExtracting(
                  nonceOffset..<(nonceOffset + HPKEAEAD.nonceByteCount)
                )
                try HPKESHA256LabeledKDF.expand(
                  preparedInnerContext: preparedInner,
                  preparedOuterContext: preparedOuter,
                  suiteID: suiteID.span,
                  label: "base_nonce",
                  outputByteCount: nonce.count,
                  updateInfo: { context throws(CryptoInputError) in
                    try context.update(modeSpan)
                    try context.update(contextSpan)
                  },
                  into: &nonce
                )
                let exporterOffset = nonceOffset + HPKEAEAD.nonceByteCount
                var exporter = destination._mutatingExtracting(
                  exporterOffset..<stateByteCount
                )
                try HPKESHA256LabeledKDF.expand(
                  preparedInnerContext: preparedInner,
                  preparedOuterContext: preparedOuter,
                  suiteID: suiteID.span,
                  label: "exp",
                  outputByteCount: exporter.count,
                  updateInfo: { context throws(CryptoInputError) in
                    try context.update(modeSpan)
                    try context.update(contextSpan)
                  },
                  into: &exporter
                )
              }
            }
          }
        }
      }
    } catch {
      throw .primitive(error)
    }
    let cipher = try withUnsafeBytes(of: &key) {
      rawKeyBytes throws(HPKEError) -> HPKEAEADContext in
      let keyBytes = rawKeyBytes.bindMemory(to: UInt8.self)
      let keySpan = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: keyBytes.baseAddress.unsafelyUnwrapped,
          count: aead.keyByteCount
        )
      )
      return try HPKEAEADContext(key: keySpan, algorithm: aead)
    }
    return HPKEContextMaterial(
      secretState: consume secretState,
      cipher: consume cipher,
      kdf: .sha256,
      aead: aead,
      kemIdentifier: kemIdentifier
    )
  }

  static func export(
    secret: Span<UInt8>,
    exporterContext: Span<UInt8>,
    length: Int,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    kemIdentifier: UInt16
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    guard length <= 65_535 else { throw .exporterLengthOutOfRange(length) }
    let suiteID = hpkeSuiteID(kemIdentifier: kemIdentifier, kdf: kdf, aead: aead)
    let value = try labeledExpand(
      prk: secret,
      label: "sec",
      info: exporterContext,
      length: length,
      suiteID: suiteID.span,
      kdf: kdf
    )
    return value
  }

  private static func labeledExtract(
    salt: Span<UInt8>,
    label: String,
    input: Span<UInt8>,
    suiteID: Span<UInt8>,
    kdf: HPKEKDF
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    var labeled = ContiguousArray<UInt8>()
    defer { wipe(&labeled) }
    append(&labeled, version.span)
    append(&labeled, suiteID)
    append(&labeled, label)
    append(&labeled, input)
    return try hmac(message: labeled.span, key: salt, kdf: kdf)
  }

  private static func labeledExpand(
    prk: Span<UInt8>,
    label: String,
    info: Span<UInt8>,
    length: Int,
    suiteID: Span<UInt8>,
    kdf: HPKEKDF
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    guard length >= 0, length <= 65_535,
      length <= 255 * kdf.digestByteCount
    else {
      throw .exporterLengthOutOfRange(length)
    }
    var labeled = ContiguousArray<UInt8>()
    defer { wipe(&labeled) }
    labeled.append(UInt8(truncatingIfNeeded: length >> 8))
    labeled.append(UInt8(truncatingIfNeeded: length))
    append(&labeled, version.span)
    append(&labeled, suiteID)
    append(&labeled, label)
    append(&labeled, info)
    var output = ContiguousArray<UInt8>(repeating: 0, count: length)
    var destination = output.mutableSpan
    do {
      switch kdf {
      case .sha256:
        try HKDFSHA256.expand(pseudorandomKey: prk, info: labeled.span, into: &destination)
      case .sha384:
        try HKDFSHA384.expand(pseudorandomKey: prk, info: labeled.span, into: &destination)
      case .sha512:
        try HKDFSHA512.expand(pseudorandomKey: prk, info: labeled.span, into: &destination)
      }
    } catch let error { throw .keyDerivation(error) }
    return output
  }

  private static func hmac(
    message: Span<UInt8>,
    key: Span<UInt8>,
    kdf: HPKEKDF
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: kdf.digestByteCount)
    var destination = output.mutableSpan
    do {
      switch kdf {
      case .sha256:
        try HMACSHA256.authenticate(message, using: key, into: &destination)
      case .sha384:
        try HMACSHA384.authenticate(message, using: key, into: &destination)
      case .sha512:
        try HMACSHA512.authenticate(message, using: key, into: &destination)
      }
    } catch { throw .primitive(error) }
    return output
  }

  private static let x25519KEMSuiteID = makeKEMSuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier
  )
  private static let p256KEMSuiteID = makeKEMSuiteID(
    kemIdentifier: HPKEP256.kemIdentifier
  )

  private static let x25519SHA256AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha256,
    aead: .aes128GCM
  )
  private static let x25519SHA256AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha256,
    aead: .aes256GCM
  )
  private static let x25519SHA256ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha256,
    aead: .chaCha20Poly1305
  )
  private static let x25519SHA384AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha384,
    aead: .aes128GCM
  )
  private static let x25519SHA384AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha384,
    aead: .aes256GCM
  )
  private static let x25519SHA384ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha384,
    aead: .chaCha20Poly1305
  )
  private static let x25519SHA512AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha512,
    aead: .aes128GCM
  )
  private static let x25519SHA512AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha512,
    aead: .aes256GCM
  )
  private static let x25519SHA512ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEX25519.kemIdentifier,
    kdf: .sha512,
    aead: .chaCha20Poly1305
  )

  private static let p256SHA256AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha256,
    aead: .aes128GCM
  )
  private static let p256SHA256AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha256,
    aead: .aes256GCM
  )
  private static let p256SHA256ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha256,
    aead: .chaCha20Poly1305
  )
  private static let p256SHA384AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha384,
    aead: .aes128GCM
  )
  private static let p256SHA384AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha384,
    aead: .aes256GCM
  )
  private static let p256SHA384ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha384,
    aead: .chaCha20Poly1305
  )
  private static let p256SHA512AES128SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha512,
    aead: .aes128GCM
  )
  private static let p256SHA512AES256SuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha512,
    aead: .aes256GCM
  )
  private static let p256SHA512ChaChaSuiteID = makeHPKESuiteID(
    kemIdentifier: HPKEP256.kemIdentifier,
    kdf: .sha512,
    aead: .chaCha20Poly1305
  )

  @inline(__always)
  private static func hpkeSuiteID(
    kemIdentifier: UInt16,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) -> ContiguousArray<UInt8> {
    switch (kemIdentifier, kdf, aead) {
    case (HPKEX25519.kemIdentifier, .sha256, .aes128GCM):
      x25519SHA256AES128SuiteID
    case (HPKEX25519.kemIdentifier, .sha256, .aes256GCM):
      x25519SHA256AES256SuiteID
    case (HPKEX25519.kemIdentifier, .sha256, .chaCha20Poly1305):
      x25519SHA256ChaChaSuiteID
    case (HPKEX25519.kemIdentifier, .sha384, .aes128GCM):
      x25519SHA384AES128SuiteID
    case (HPKEX25519.kemIdentifier, .sha384, .aes256GCM):
      x25519SHA384AES256SuiteID
    case (HPKEX25519.kemIdentifier, .sha384, .chaCha20Poly1305):
      x25519SHA384ChaChaSuiteID
    case (HPKEX25519.kemIdentifier, .sha512, .aes128GCM):
      x25519SHA512AES128SuiteID
    case (HPKEX25519.kemIdentifier, .sha512, .aes256GCM):
      x25519SHA512AES256SuiteID
    case (HPKEX25519.kemIdentifier, .sha512, .chaCha20Poly1305):
      x25519SHA512ChaChaSuiteID
    case (HPKEP256.kemIdentifier, .sha256, .aes128GCM):
      p256SHA256AES128SuiteID
    case (HPKEP256.kemIdentifier, .sha256, .aes256GCM):
      p256SHA256AES256SuiteID
    case (HPKEP256.kemIdentifier, .sha256, .chaCha20Poly1305):
      p256SHA256ChaChaSuiteID
    case (HPKEP256.kemIdentifier, .sha384, .aes128GCM):
      p256SHA384AES128SuiteID
    case (HPKEP256.kemIdentifier, .sha384, .aes256GCM):
      p256SHA384AES256SuiteID
    case (HPKEP256.kemIdentifier, .sha384, .chaCha20Poly1305):
      p256SHA384ChaChaSuiteID
    case (HPKEP256.kemIdentifier, .sha512, .aes128GCM):
      p256SHA512AES128SuiteID
    case (HPKEP256.kemIdentifier, .sha512, .aes256GCM):
      p256SHA512AES256SuiteID
    case (HPKEP256.kemIdentifier, .sha512, .chaCha20Poly1305):
      p256SHA512ChaChaSuiteID
    default:
      preconditionFailure("HPKE context contains a validated KEM identifier")
    }
  }

  private static func makeHPKESuiteID(
    kemIdentifier: UInt16,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) -> ContiguousArray<UInt8> {
    ContiguousArray([
      0x48, 0x50, 0x4B, 0x45,
      UInt8(truncatingIfNeeded: kemIdentifier >> 8),
      UInt8(truncatingIfNeeded: kemIdentifier),
      UInt8(truncatingIfNeeded: kdf.identifier >> 8),
      UInt8(truncatingIfNeeded: kdf.identifier),
      UInt8(truncatingIfNeeded: aead.identifier >> 8),
      UInt8(truncatingIfNeeded: aead.identifier),
    ])
  }

  private static func makeKEMSuiteID(
    kemIdentifier: UInt16
  ) -> ContiguousArray<UInt8> {
    ContiguousArray([
      0x4B, 0x45, 0x4D,
      UInt8(truncatingIfNeeded: kemIdentifier >> 8),
      UInt8(truncatingIfNeeded: kemIdentifier),
    ])
  }

  private static func kemSuiteID(
    for kemIdentifier: UInt16
  ) -> ContiguousArray<UInt8> {
    switch kemIdentifier {
    case HPKEX25519.kemIdentifier: x25519KEMSuiteID
    case HPKEP256.kemIdentifier: p256KEMSuiteID
    default: preconditionFailure("HPKE uses a validated KEM identifier")
    }
  }

  private static let emptyBytes = ContiguousArray<UInt8>()

  private static func append(
    _ destination: inout ContiguousArray<UInt8>,
    _ source: Span<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  private static func copy(
    _ source: Span<UInt8>,
    into destination: inout MutableSpan<UInt8>,
    at offset: Int
  ) {
    var index = 0
    while index < source.count {
      destination[offset + index] = source[index]
      index += 1
    }
  }

  private static func append(
    _ destination: inout ContiguousArray<UInt8>,
    _ source: String
  ) {
    for byte in source.utf8 { destination.append(byte) }
  }

  fileprivate static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }

  private static func wipe(_ bytes: inout SIMD32<UInt8>) {
    withUnsafeMutableBytes(of: &bytes) { buffer in
      SecureWipe.erase(
        buffer.baseAddress.unsafelyUnwrapped,
        byteCount: buffer.count
      )
    }
  }

  private static func wipe(_ bytes: inout SIMD64<UInt8>) {
    withUnsafeMutableBytes(of: &bytes) { buffer in
      SecureWipe.erase(
        buffer.baseAddress.unsafelyUnwrapped,
        byteCount: buffer.count
      )
    }
  }
}
