import SwiftSSLCore

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
  private let kdf: HPKEKDF
  private let aead: HPKEAEAD
  private var sequence: UInt64

  fileprivate init(material: consuming HPKEContextMaterial) {
    kdf = material.kdf
    aead = material.aead
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
    try withKeyAndNonce { keyBytes, nonce throws(HPKEError) in
      try HPKEPrimitives.seal(
        plaintext: plaintext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        key: keyBytes,
        aead: aead,
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
      let offset = aead.keyByteCount + HPKEAEAD.nonceByteCount
      let secret = state.extracting(offset..<state.count)
      let value = try HPKEPrimitives.export(
        secret: secret,
        exporterContext: exporterContext,
        length: length,
        kdf: kdf,
        aead: aead
      )
      return try HPKEExportedSecret(consuming: value)
    }
  }

  private borrowing func withKeyAndNonce<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>, Span<UInt8>) throws(Failure) -> Result
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
        let baseNonce = state.extracting(
          aead.keyByteCount..<(aead.keyByteCount + HPKEAEAD.nonceByteCount)
        )
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
        return try body(state.extracting(0..<aead.keyByteCount), nonce)
      }
    }
  }
}

/// The recipient side of one X25519/HKDF/AEAD HPKE context.
public struct HPKERecipientContext: ~Copyable, Sendable {
  private let secretState: SecretBytes
  private let kdf: HPKEKDF
  private let aead: HPKEAEAD
  private var sequence: UInt64

  fileprivate init(material: consuming HPKEContextMaterial) {
    kdf = material.kdf
    aead = material.aead
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
    try withKeyAndNonce { keyBytes, nonce throws(HPKEError) in
      try HPKEPrimitives.open(
        ciphertext: ciphertext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        key: keyBytes,
        aead: aead,
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
      let offset = aead.keyByteCount + HPKEAEAD.nonceByteCount
      let secret = state.extracting(offset..<state.count)
      let value = try HPKEPrimitives.export(
        secret: secret,
        exporterContext: exporterContext,
        length: length,
        kdf: kdf,
        aead: aead
      )
      return try HPKEExportedSecret(consuming: value)
    }
  }

  private borrowing func withKeyAndNonce<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>, Span<UInt8>) throws(Failure) -> Result
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
        let baseNonce = state.extracting(
          aead.keyByteCount..<(aead.keyByteCount + HPKEAEAD.nonceByteCount)
        )
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
        return try body(state.extracting(0..<aead.keyByteCount), nonce)
      }
    }
  }
}

public struct HPKESenderSetup: ~Copyable, Sendable {
  public let encapsulation: OwnedBytes
  public let context: HPKESenderContext

  fileprivate init(
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
    let dh = try sharedSecretBytes(
      privateKey: ephemeral,
      peerPublicKey: recipientPublicKey
    )
    let enc = OwnedBytes(copying: encapsulation.span)
    let material = try finishSender(
      mode: mode,
      dh: consume dh,
      encapsulation: encapsulation.span,
      recipientPublicKey: recipientPublicKey.span,
      senderPublicKey: nil,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
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
    var dh = try sharedSecretBytes(
      privateKey: ephemeral,
      peerPublicKey: recipientPublicKey
    )
    var authenticated = try sharedSecretBytes(
      privateKey: senderKeyPair.privateKey,
      peerPublicKey: recipientPublicKey
    )
    dh.append(contentsOf: authenticated)
    wipe(&authenticated)
    let enc = OwnedBytes(copying: encapsulation.span)
    let senderPublic = copy(senderKeyPair.publicKey.span)
    let material = try finishSender(
      mode: mode,
      dh: consume dh,
      encapsulation: encapsulation.span,
      recipientPublicKey: recipientPublicKey.span,
      senderPublicKey: senderPublic,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
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
    var dh = try sharedSecretBytes(
      privateKey: recipientKeyPair.privateKey,
      peerPublicKeyBytes: encapsulation
    )
    if let senderPublicKey {
      let sender: X25519PublicKey
      do { sender = try X25519PublicKey(bytes: senderPublicKey.span) } catch {
        throw .invalidConfiguration
      }
      var authenticated = try sharedSecretBytes(
        privateKey: recipientKeyPair.privateKey,
        peerPublicKey: sender
      )
      dh.append(contentsOf: authenticated)
      wipe(&authenticated)
    }
    let material = try finishSender(
      mode: mode,
      dh: consume dh,
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

  private static func finishSender(
    mode: HPKEMode,
    dh: consuming ContiguousArray<UInt8>,
    encapsulation: Span<UInt8>,
    recipientPublicKey: Span<UInt8>,
    senderPublicKey: ContiguousArray<UInt8>?,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    var dh = dh
    defer { wipe(&dh) }
    return try HPKEPrimitives.withKEMSharedSecret(
      dh: dh.span,
      encapsulation: encapsulation,
      recipientPublicKey: recipientPublicKey,
      senderPublicKey: senderPublicKey
    ) { sharedSecret throws(HPKEError) -> HPKEContextMaterial in
      try HPKEPrimitives.deriveContext(
        sharedSecret: sharedSecret,
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

  private static func sharedSecretBytes(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKey: borrowing X25519PublicKey
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    try sharedSecretBytes(
      privateKey: privateKey,
      peerPublicKeyBytes: peerPublicKey.span
    )
  }

  private static func sharedSecretBytes(
    privateKey: borrowing X25519PrivateKey,
    peerPublicKeyBytes: Span<UInt8>
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    var shared = ContiguousArray<UInt8>(
      repeating: 0,
      count: X25519.sharedSecretByteCount
    )
    do {
      var destination = shared.mutableSpan
      try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKeyBytes: peerPublicKeyBytes,
        into: &destination
      )
    } catch let error {
      throw .primitive(error)
    }
    return shared
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

private struct HPKEContextMaterial: ~Copyable, Sendable {
  let secretState: SecretBytes
  let kdf: HPKEKDF
  let aead: HPKEAEAD
}

private enum HPKEPrimitives {
  private static let version = ContiguousArray<UInt8>([0x48, 0x50, 0x4B, 0x45, 0x2D, 0x76, 0x31])
  private static let kemSuiteID = ContiguousArray<UInt8>([0x4B, 0x45, 0x4D, 0x00, 0x20])

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
    dh: Span<UInt8>,
    encapsulation: Span<UInt8>,
    recipientPublicKey: Span<UInt8>,
    senderPublicKey: ContiguousArray<UInt8>?,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    var eaePRK = SIMD32<UInt8>(repeating: 0)
    var sharedSecret = SIMD32<UInt8>(repeating: 0)
    defer {
      wipe(&eaePRK)
      wipe(&sharedSecret)
    }
    do {
      try withUnsafeMutableBytes(of: &eaePRK) {
        bytes throws(CryptoInputError) in
        let pointer = bytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        var output = MutableSpan(
          _unsafeStart: pointer,
          count: SHA256.digestByteCount
        )
        try HPKESHA256LabeledKDF.extract(
          salt: emptyBytes.span,
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
      return try body(shared)
    }
  }

  static func deriveContext(
    sharedSecret: Span<UInt8>,
    mode: HPKEMode,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    if kdf == .sha256 {
      return try deriveSHA256Context(
        sharedSecret: sharedSecret,
        mode: mode,
        info: info,
        psk: psk,
        pskID: pskID,
        aead: aead
      )
    }
    let suiteID = hpkeSuiteID(kdf: kdf, aead: aead)
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
    let totalByteCount = key.count + baseNonce.count + exporterSecret.count
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(totalByteCount)
    } catch let error {
      throw .secretMemory(error)
    }
    let secretState = SecretBytes(byteCount: byteCount) { destination in
      copy(key.span, into: &destination, at: 0)
      copy(baseNonce.span, into: &destination, at: key.count)
      copy(
        exporterSecret.span,
        into: &destination,
        at: key.count + baseNonce.count
      )
    }
    return HPKEContextMaterial(
      secretState: consume secretState,
      kdf: kdf,
      aead: aead
    )
  }

  private static func deriveSHA256Context(
    sharedSecret: Span<UInt8>,
    mode: HPKEMode,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    let suiteID = hpkeSuiteID(kdf: .sha256, aead: aead)
    var contextHashes = SIMD64<UInt8>(repeating: 0)
    var secret = SIMD32<UInt8>(repeating: 0)
    defer {
      wipe(&contextHashes)
      wipe(&secret)
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
          salt: emptyBytes.span,
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
          salt: emptyBytes.span,
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

    let stateByteCount =
      aead.keyByteCount
      + HPKEAEAD.nonceByteCount
      + SHA256.digestByteCount
    let validatedByteCount: SecretByteCount
    do {
      validatedByteCount = try SecretByteCount(stateByteCount)
    } catch let error {
      throw .secretMemory(error)
    }

    let secretState: SecretBytes
    do {
      secretState = try withUnsafeBytes(of: &secret) {
        secretBytes throws(CryptoInputError) -> SecretBytes in
        let secretPointer = secretBytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: UInt8.self)
        let secretSpan = Span(
          _unsafeElements: UnsafeBufferPointer(
            start: secretPointer,
            count: SHA256.digestByteCount
          )
        )
        return try withUnsafeBytes(of: &contextHashes) {
          contextBytes throws(CryptoInputError) -> SecretBytes in
          let contextPointer = contextBytes.baseAddress.unsafelyUnwrapped
            .assumingMemoryBound(to: UInt8.self)
          let contextSpan = Span(
            _unsafeElements: UnsafeBufferPointer(
              start: contextPointer,
              count: contextBytes.count
            )
          )
          return try SecretBytes(byteCount: validatedByteCount) {
            destination throws(CryptoInputError) in
            var modeByte = mode.encoded
            try withUnsafeBytes(of: &modeByte) {
              modeBytes throws(CryptoInputError) in
              let modeSpan = Span(
                _unsafeElements: modeBytes.bindMemory(to: UInt8.self)
              )
              var key = destination._mutatingExtracting(
                0..<aead.keyByteCount
              )
              try HPKESHA256LabeledKDF.expand(
                pseudorandomKey: secretSpan,
                suiteID: suiteID.span,
                label: "key",
                outputByteCount: key.count,
                updateInfo: { context throws(CryptoInputError) in
                  try context.update(modeSpan)
                  try context.update(contextSpan)
                },
                into: &key
              )
              let nonceOffset = aead.keyByteCount
              var nonce = destination._mutatingExtracting(
                nonceOffset..<(nonceOffset + HPKEAEAD.nonceByteCount)
              )
              try HPKESHA256LabeledKDF.expand(
                pseudorandomKey: secretSpan,
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
                pseudorandomKey: secretSpan,
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
    } catch {
      throw .primitive(error)
    }
    return HPKEContextMaterial(
      secretState: consume secretState,
      kdf: .sha256,
      aead: aead
    )
  }

  static func export(
    secret: Span<UInt8>,
    exporterContext: Span<UInt8>,
    length: Int,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    guard length <= 65_535 else { throw .exporterLengthOutOfRange(length) }
    let suiteID = hpkeSuiteID(kdf: kdf, aead: aead)
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

  static func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    key: Span<UInt8>,
    aead: HPKEAEAD,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    do {
      switch aead {
      case .aes128GCM, .aes256GCM:
        var cipher = try AESGCM(key: key)
        try cipher.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      case .chaCha20Poly1305:
        var cipher = try ChaCha20Poly1305(key: key)
        try cipher.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      }
    } catch let error { throw .authenticatedCipher(error) }
  }

  static func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    key: Span<UInt8>,
    aead: HPKEAEAD,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    do {
      switch aead {
      case .aes128GCM, .aes256GCM:
        var cipher = try AESGCM(key: key)
        try cipher.open(
          ciphertextAndTag: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      case .chaCha20Poly1305:
        var cipher = try ChaCha20Poly1305(key: key)
        try cipher.open(
          ciphertextAndTag: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      }
    } catch let error { throw .authenticatedCipher(error) }
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

  private static func hpkeSuiteID(
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) -> ContiguousArray<UInt8> {
    ContiguousArray([
      0x48, 0x50, 0x4B, 0x45,
      UInt8(truncatingIfNeeded: HPKEX25519.kemIdentifier >> 8),
      UInt8(truncatingIfNeeded: HPKEX25519.kemIdentifier),
      UInt8(truncatingIfNeeded: kdf.identifier >> 8),
      UInt8(truncatingIfNeeded: kdf.identifier),
      UInt8(truncatingIfNeeded: aead.identifier >> 8),
      UInt8(truncatingIfNeeded: aead.identifier),
    ])
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
