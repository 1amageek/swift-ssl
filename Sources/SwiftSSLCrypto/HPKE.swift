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
  case entropy(EntropyError)
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
    } catch {
      throw .primitive(.invalidLength(expected: 1, actual: bytes.count))
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

  fileprivate init(material: consuming HPKEContextMaterial) throws(HPKEError) {
    kdf = material.kdf
    aead = material.aead
    var material = material
    var packed = material.key
    packed.append(contentsOf: material.baseNonce)
    packed.append(contentsOf: material.exporterSecret)
    material.erase()
    secretState = try HPKEPrimitives.makeSecret(consume packed)
    sequence = 0
  }

  public var sequenceNumber: UInt64 { sequence }

  public mutating func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(HPKEError) -> OwnedBytes {
    guard sequence < UInt64.max else { throw .sequenceExhausted }
    let nonce = makeNonce()
    let (required, overflow) = plaintext.count.addingReportingOverflow(
      HPKEAEAD.tagByteCount
    )
    guard !overflow else { throw .authenticatedCipher(.messageLimitReached) }
    var output = ContiguousArray<UInt8>(repeating: 0, count: required)
    do {
      try secretState.withBorrowedBytes { state throws(HPKEError) in
        let keyBytes = state.extracting(0..<aead.keyByteCount)
        try HPKEPrimitives.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce.span,
          key: keyBytes,
          aead: aead,
          into: &output
        )
      }
    } catch let error {
      throw error
    }
    sequence += 1
    return OwnedBytes(consuming: output)
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

  private func makeNonce() -> ContiguousArray<UInt8> {
    var nonce = ContiguousArray<UInt8>(repeating: 0, count: HPKEAEAD.nonceByteCount)
    secretState.withBorrowedBytes { state in
      let bytes = state.extracting(
        aead.keyByteCount..<(aead.keyByteCount + HPKEAEAD.nonceByteCount))
      var index = 0
      while index < nonce.count {
        nonce[index] = bytes[index]
        index += 1
      }
    }
    var index = 0
    while index < MemoryLayout<UInt64>.size {
      nonce[nonce.count - 1 - index] ^= UInt8(truncatingIfNeeded: sequence >> UInt64(index * 8))
      index += 1
    }
    return nonce
  }
}

/// The recipient side of one X25519/HKDF/AEAD HPKE context.
public struct HPKERecipientContext: ~Copyable, Sendable {
  private let secretState: SecretBytes
  private let kdf: HPKEKDF
  private let aead: HPKEAEAD
  private var sequence: UInt64

  fileprivate init(material: consuming HPKEContextMaterial) throws(HPKEError) {
    kdf = material.kdf
    aead = material.aead
    var material = material
    var packed = material.key
    packed.append(contentsOf: material.baseNonce)
    packed.append(contentsOf: material.exporterSecret)
    material.erase()
    secretState = try HPKEPrimitives.makeSecret(consume packed)
    sequence = 0
  }

  public var sequenceNumber: UInt64 { sequence }

  public mutating func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws(HPKEError) -> OwnedBytes {
    guard sequence < UInt64.max else { throw .sequenceExhausted }
    guard ciphertext.count >= HPKEAEAD.tagByteCount else {
      throw .authenticatedCipher(
        .outputTooSmall(
          required: HPKEAEAD.tagByteCount,
          actual: ciphertext.count
        )
      )
    }
    let nonce = makeNonce()
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: ciphertext.count - HPKEAEAD.tagByteCount
    )
    do {
      try secretState.withBorrowedBytes { state throws(HPKEError) in
        let keyBytes = state.extracting(0..<aead.keyByteCount)
        try HPKEPrimitives.open(
          ciphertext: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce.span,
          key: keyBytes,
          aead: aead,
          into: &output
        )
      }
    } catch let error {
      throw error
    }
    sequence += 1
    return OwnedBytes(consuming: output)
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

  private func makeNonce() -> ContiguousArray<UInt8> {
    var nonce = ContiguousArray<UInt8>(repeating: 0, count: HPKEAEAD.nonceByteCount)
    secretState.withBorrowedBytes { state in
      let bytes = state.extracting(
        aead.keyByteCount..<(aead.keyByteCount + HPKEAEAD.nonceByteCount))
      var index = 0
      while index < nonce.count {
        nonce[index] = bytes[index]
        index += 1
      }
    }
    var index = 0
    while index < MemoryLayout<UInt64>.size {
      nonce[nonce.count - 1 - index] ^= UInt8(truncatingIfNeeded: sequence >> UInt64(index * 8))
      index += 1
    }
    return nonce
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
    senderPrivateKey: borrowing X25519PrivateKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeAuthSender(
      mode: .auth,
      recipientPublicKey: recipientPublicKey,
      senderPrivateKey: senderPrivateKey,
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
    senderPrivateKey: borrowing X25519PrivateKey,
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
      senderPrivateKey: senderPrivateKey,
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
    recipientPrivateKey: borrowing X25519PrivateKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeRecipient(
      mode: .base,
      encapsulation: encapsulation,
      recipientPrivateKey: recipientPrivateKey,
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
    recipientPrivateKey: borrowing X25519PrivateKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeRecipient(
      mode: .psk,
      encapsulation: encapsulation,
      recipientPrivateKey: recipientPrivateKey,
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
    recipientPrivateKey: borrowing X25519PrivateKey,
    senderPublicKey: borrowing X25519PublicKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    let sender = senderPublicKey.withBorrowedBytes { copy($0) }
    return try makeRecipient(
      mode: .auth,
      encapsulation: encapsulation,
      recipientPrivateKey: recipientPrivateKey,
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
    recipientPrivateKey: borrowing X25519PrivateKey,
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
      recipientPrivateKey: recipientPrivateKey,
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
      switch error {
      case .entropy(let value): throw .entropy(value)
      case .memoryFailure:
        throw .primitive(.invalidLength(expected: 1, actual: 0))
      }
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
      encapsulation: enc,
      recipientPublicKey: recipientPublicKey.withBorrowedBytes { copy($0) },
      senderPublicKey: nil,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
    let context = try HPKESenderContext(material: consume material)
    return HPKESenderSetup(
      encapsulation: consume enc,
      context: consume context
    )
  }

  private static func makeAuthSender(
    mode: HPKEMode,
    recipientPublicKey: borrowing X25519PublicKey,
    senderPrivateKey: borrowing X25519PrivateKey,
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
      switch error {
      case .entropy(let value): throw .entropy(value)
      case .memoryFailure:
        throw .primitive(.invalidLength(expected: 1, actual: 0))
      }
    }
    let encapsulation = ephemeral.publicKey()
    var dh = try sharedSecretBytes(
      privateKey: ephemeral,
      peerPublicKey: recipientPublicKey
    )
    var authenticated = try sharedSecretBytes(
      privateKey: senderPrivateKey,
      peerPublicKey: recipientPublicKey
    )
    dh.append(contentsOf: authenticated)
    wipe(&authenticated)
    let enc = OwnedBytes(copying: encapsulation.span)
    let senderPublic = copy(senderPrivateKey.publicKey().span)
    let material = try finishSender(
      mode: mode,
      dh: consume dh,
      encapsulation: enc,
      recipientPublicKey: recipientPublicKey.withBorrowedBytes { copy($0) },
      senderPublicKey: senderPublic,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
    let context = try HPKESenderContext(material: consume material)
    return HPKESenderSetup(
      encapsulation: consume enc,
      context: consume context
    )
  }

  private static func makeRecipient(
    mode: HPKEMode,
    encapsulation: Span<UInt8>,
    recipientPrivateKey: borrowing X25519PrivateKey,
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
    let ephemeralPublic: X25519PublicKey
    do {
      ephemeralPublic = try X25519PublicKey(bytes: encapsulation)
    } catch { throw .invalidEncapsulation }
    var dh = try sharedSecretBytes(
      privateKey: recipientPrivateKey,
      peerPublicKey: ephemeralPublic
    )
    if let senderPublicKey {
      let sender: X25519PublicKey
      do { sender = try X25519PublicKey(bytes: senderPublicKey.span) } catch {
        throw .invalidConfiguration
      }
      var authenticated = try sharedSecretBytes(
        privateKey: recipientPrivateKey,
        peerPublicKey: sender
      )
      dh.append(contentsOf: authenticated)
      wipe(&authenticated)
    }
    let recipientPublic = copy(recipientPrivateKey.publicKey().span)
    let material = try finishSender(
      mode: mode,
      dh: consume dh,
      encapsulation: OwnedBytes(copying: encapsulation),
      recipientPublicKey: recipientPublic,
      senderPublicKey: senderPublicKey,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
    return try HPKERecipientContext(material: consume material)
  }

  private static func finishSender(
    mode: HPKEMode,
    dh: consuming ContiguousArray<UInt8>,
    encapsulation: borrowing OwnedBytes,
    recipientPublicKey: ContiguousArray<UInt8>,
    senderPublicKey: ContiguousArray<UInt8>?,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKEContextMaterial {
    var dh = dh
    defer { wipe(&dh) }
    var kemContext = ContiguousArray<UInt8>()
    kemContext.reserveCapacity(
      encapsulation.count + recipientPublicKey.count + (senderPublicKey?.count ?? 0))
    append(&kemContext, encapsulation.span)
    append(&kemContext, recipientPublicKey.span)
    if let senderPublicKey { append(&kemContext, senderPublicKey.span) }
    var sharedSecret = try HPKEPrimitives.kemExtractAndExpand(
      dh: dh.span,
      kemContext: kemContext.span
    )
    defer { wipe(&sharedSecret) }
    return try HPKEPrimitives.deriveContext(
      sharedSecret: sharedSecret.span,
      mode: mode,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
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
    let shared: X25519SharedSecret
    do {
      shared = try X25519.sharedSecret(
        privateKey: privateKey,
        peerPublicKey: peerPublicKey
      )
    } catch let error {
      throw .primitive(error)
    }
    return shared.withBorrowedBytes { copy($0) }
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
  var key: ContiguousArray<UInt8>
  var baseNonce: ContiguousArray<UInt8>
  var exporterSecret: ContiguousArray<UInt8>
  let kdf: HPKEKDF
  let aead: HPKEAEAD

  mutating func erase() {
    HPKEPrimitives.wipe(&key)
    HPKEPrimitives.wipe(&baseNonce)
    HPKEPrimitives.wipe(&exporterSecret)
  }
}

private enum HPKEPrimitives {
  private static let version = ContiguousArray<UInt8>([0x48, 0x50, 0x4B, 0x45, 0x2D, 0x76, 0x31])
  private static let kemSuiteID = ContiguousArray<UInt8>([0x4B, 0x45, 0x4D, 0x00, 0x20])

  static func makeSecret(
    _ bytes: consuming ContiguousArray<UInt8>
  ) throws(HPKEError) -> SecretBytes {
    var bytes = bytes
    defer { wipe(&bytes) }
    do { return try SecretBytes(copying: bytes.span) } catch {
      throw .primitive(.invalidLength(expected: 1, actual: bytes.count))
    }
  }

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

  static func kemExtractAndExpand(
    dh: Span<UInt8>,
    kemContext: Span<UInt8>
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    var eaePRK = try labeledExtract(
      salt: emptyBytes.span,
      label: "eae_prk",
      input: dh,
      suiteID: kemSuiteID.span,
      kdf: .sha256
    )
    defer { wipe(&eaePRK) }
    return try labeledExpand(
      prk: eaePRK.span,
      label: "shared_secret",
      info: kemContext,
      length: SHA256.digestByteCount,
      suiteID: kemSuiteID.span,
      kdf: .sha256
    )
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
    let key = try labeledExpand(
      prk: secret.span,
      label: "key",
      info: context.span,
      length: aead.keyByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    let baseNonce = try labeledExpand(
      prk: secret.span,
      label: "base_nonce",
      info: context.span,
      length: HPKEAEAD.nonceByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    let exporterSecret = try labeledExpand(
      prk: secret.span,
      label: "exp",
      info: context.span,
      length: kdf.digestByteCount,
      suiteID: suiteID.span,
      kdf: kdf
    )
    return HPKEContextMaterial(
      key: key,
      baseNonce: baseNonce,
      exporterSecret: exporterSecret,
      kdf: kdf,
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
    into output: inout ContiguousArray<UInt8>
  ) throws(HPKEError) {
    do {
      switch aead {
      case .aes128GCM, .aes256GCM:
        var cipher = try AESGCM(key: key)
        var destination = output.mutableSpan
        try cipher.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &destination
        )
      case .chaCha20Poly1305:
        var cipher = try ChaCha20Poly1305(key: key)
        var destination = output.mutableSpan
        try cipher.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &destination
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
    into output: inout ContiguousArray<UInt8>
  ) throws(HPKEError) {
    do {
      switch aead {
      case .aes128GCM, .aes256GCM:
        var cipher = try AESGCM(key: key)
        var destination = output.mutableSpan
        try cipher.open(
          ciphertextAndTag: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &destination
        )
      case .chaCha20Poly1305:
        var cipher = try ChaCha20Poly1305(key: key)
        var destination = output.mutableSpan
        try cipher.open(
          ciphertextAndTag: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &destination
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
    } catch { throw .primitive(.invalidSignature) }
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
}
