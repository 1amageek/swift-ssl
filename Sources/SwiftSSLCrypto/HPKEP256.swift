import SwiftSSLCore

/// RFC 9180 DHKEM(P-256, HKDF-SHA256) with Base, PSK, Auth, and AuthPSK
/// setup modes.
public enum HPKEP256 {
  public static let kemIdentifier: UInt16 = 0x0010

  public static func setupBaseSender(
    recipientPublicKey: borrowing P256PublicKey,
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

  /// Creates a Base-mode sender from one borrowed uncompressed SEC 1 key.
  ///
  /// This entry point validates and consumes the public point for this setup
  /// only. Callers that reuse a validated key should use the typed-key overload,
  /// which retains its immutable scalar-multiplication precomputation.
  public static func setupBaseSender(
    recipientPublicKeyBytes: Span<UInt8>,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD,
    using entropy: borrowing any EntropySource
  ) throws(HPKEError) -> HPKESenderSetup {
    try makeEncodedSender(
      mode: .base,
      recipientPublicKeyBytes: recipientPublicKeyBytes,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead,
      using: entropy
    )
  }

  public static func setupPSKSender(
    recipientPublicKey: borrowing P256PublicKey,
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
    recipientPublicKey: borrowing P256PublicKey,
    senderKeyPair: borrowing P256KeyPair,
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
    recipientPublicKey: borrowing P256PublicKey,
    senderKeyPair: borrowing P256KeyPair,
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
    recipientKeyPair: borrowing P256KeyPair,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeRecipient(
      mode: .base,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupPSKRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing P256KeyPair,
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
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupAuthRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing P256KeyPair,
    senderPublicKey: borrowing P256PublicKey,
    info: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeAuthenticatedRecipient(
      mode: .auth,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: senderPublicKey,
      info: info,
      psk: emptyBytes.span,
      pskID: emptyBytes.span,
      kdf: kdf,
      aead: aead
    )
  }

  public static func setupAuthPSKRecipient(
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing P256KeyPair,
    senderPublicKey: borrowing P256PublicKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try makeAuthenticatedRecipient(
      mode: .authPSK,
      encapsulation: encapsulation,
      recipientKeyPair: recipientKeyPair,
      senderPublicKey: senderPublicKey,
      info: info,
      psk: psk,
      pskID: pskID,
      kdf: kdf,
      aead: aead
    )
  }

  private static func makeSender(
    mode: HPKEMode,
    recipientPublicKey: borrowing P256PublicKey,
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
    let ephemeral: P256PrivateKey
    do {
      ephemeral = try P256PrivateKey.generate(using: entropy)
    } catch let error {
      throw .p256KeyGeneration(error)
    }
    let encapsulation = try encodePublicKey(ephemeral)
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
    return HPKESenderSetup(
      encapsulation: OwnedBytes(consuming: encapsulation),
      context: HPKESenderContext(material: consume material)
    )
  }

  private static func makeEncodedSender(
    mode: HPKEMode,
    recipientPublicKeyBytes: Span<UInt8>,
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
    let ephemeral: P256PrivateKey
    do {
      ephemeral = try P256PrivateKey.generate(using: entropy)
    } catch let error {
      throw .p256KeyGeneration(error)
    }
    let encapsulation = try encodePublicKey(ephemeral)
    let material = try withEncodedSharedSecret(
      privateKey: ephemeral,
      peerPublicKeyBytes: recipientPublicKeyBytes,
      mapError: { .primitive($0) }
    ) { dh throws(HPKEError) -> HPKEContextMaterial in
      try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation.span,
        recipientPublicKey: recipientPublicKeyBytes,
        senderPublicKey: nil,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
    }
    return HPKESenderSetup(
      encapsulation: OwnedBytes(consuming: encapsulation),
      context: HPKESenderContext(material: consume material)
    )
  }

  private static func makeAuthSender(
    mode: HPKEMode,
    recipientPublicKey: borrowing P256PublicKey,
    senderKeyPair: borrowing P256KeyPair,
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
    let ephemeral: P256PrivateKey
    do {
      ephemeral = try P256PrivateKey.generate(using: entropy)
    } catch let error {
      throw .p256KeyGeneration(error)
    }
    let encapsulation = try encodePublicKey(ephemeral)
    let senderPublicKey = copy(senderKeyPair.publicKey.span)
    let material = try withAuthenticatedSharedSecrets(
      firstPrivateKey: ephemeral,
      firstPeerPublicKey: recipientPublicKey,
      secondPrivateKey: senderKeyPair.privateKey,
      secondPeerPublicKey: recipientPublicKey
    ) { dh throws(HPKEError) -> HPKEContextMaterial in
      try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation.span,
        recipientPublicKey: recipientPublicKey.span,
        senderPublicKey: senderPublicKey,
        info: info,
        psk: psk,
        pskID: pskID,
        kdf: kdf,
        aead: aead
      )
    }
    return HPKESenderSetup(
      encapsulation: OwnedBytes(consuming: encapsulation),
      context: HPKESenderContext(material: consume material)
    )
  }

  private static func makeRecipient(
    mode: HPKEMode,
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing P256KeyPair,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try HPKEPrimitives.validate(mode: mode, psk: psk, pskID: pskID)
    guard mode == .base || mode == .psk else {
      throw .invalidConfiguration
    }
    return try withEncodedSharedSecret(
      privateKey: recipientKeyPair.privateKey,
      peerPublicKeyBytes: encapsulation,
      mapError: { _ in .invalidEncapsulation }
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

  private static func makeAuthenticatedRecipient(
    mode: HPKEMode,
    encapsulation: Span<UInt8>,
    recipientKeyPair: borrowing P256KeyPair,
    senderPublicKey: borrowing P256PublicKey,
    info: Span<UInt8>,
    psk: Span<UInt8>,
    pskID: Span<UInt8>,
    kdf: HPKEKDF,
    aead: HPKEAEAD
  ) throws(HPKEError) -> HPKERecipientContext {
    try HPKEPrimitives.validate(mode: mode, psk: psk, pskID: pskID)
    guard mode == .auth || mode == .authPSK else {
      throw .invalidConfiguration
    }
    let encodedSenderPublicKey = copy(senderPublicKey.span)
    return try withAuthenticatedDecapsulatedSharedSecrets(
      firstPrivateKey: recipientKeyPair.privateKey,
      firstPeerPublicKeyBytes: encapsulation,
      secondPrivateKey: recipientKeyPair.privateKey,
      secondPeerPublicKey: senderPublicKey
    ) { dh throws(HPKEError) -> HPKERecipientContext in
      let material = try finishSender(
        mode: mode,
        dh: dh,
        encapsulation: encapsulation,
        recipientPublicKey: recipientKeyPair.publicKey.span,
        senderPublicKey: encodedSenderPublicKey,
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
    try HPKEPrimitives.withKEMSharedSecret(
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

  private static func withSharedSecret<Result: ~Copyable>(
    privateKey: borrowing P256PrivateKey,
    peerPublicKey: borrowing P256PublicKey,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD owner contains exactly one initialized 32-byte P-256 x
    //   coordinate and is wiped exactly once before leaving this scope.
    // - Mutable and immutable spans are sequential, synchronous borrows of the
    //   same owner. Neither a pointer nor a span escapes or crosses Sendable.
    // - UInt8 has stride/alignment one and every offset is a fixed constant.
    var shared = SIMD32<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) { rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        var destination = MutableSpan(
          _unsafeStart: bytes.baseAddress.unsafelyUnwrapped,
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: privateKey,
          peerPublicKey: peerPublicKey,
          into: &destination
        )
      }
    } catch let error {
      throw .primitive(error)
    }
    return try withUnsafeBytes(of: &shared) { rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
    }
  }

  private static func encodePublicKey(
    _ privateKey: borrowing P256PrivateKey
  ) throws(HPKEError) -> ContiguousArray<UInt8> {
    var encoded = ContiguousArray<UInt8>(
      repeating: 0,
      count: P256PublicKey.uncompressedByteCount
    )
    do {
      var destination = encoded.mutableSpan
      try privateKey.publicKey(into: &destination)
    } catch let error {
      throw .primitive(error)
    }
    return encoded
  }

  private static func withEncodedSharedSecret<Result: ~Copyable>(
    privateKey: borrowing P256PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    mapError: (CryptoInputError) -> HPKEError,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD owner contains exactly one initialized 32-byte P-256 x
    //   coordinate and is wiped exactly once before leaving this scope.
    // - The peer bytes are decoded once into a stack value and use the
    //   bounded single-use table; no reusable comb allocation is constructed.
    // - No pointer or span escapes this synchronous function.
    var shared = SIMD32<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress.unsafelyUnwrapped, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) { rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        var destination = MutableSpan(
          _unsafeStart: bytes.baseAddress.unsafelyUnwrapped,
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: privateKey,
          peerPublicKeyBytes: peerPublicKeyBytes,
          into: &destination
        )
      }
    } catch let error {
      throw mapError(error)
    }
    return try withUnsafeBytes(of: &shared) { rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
    }
  }

  private static func withAuthenticatedSharedSecrets<Result: ~Copyable>(
    firstPrivateKey: borrowing P256PrivateKey,
    firstPeerPublicKey: borrowing P256PublicKey,
    secondPrivateKey: borrowing P256PrivateKey,
    secondPeerPublicKey: borrowing P256PublicKey,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD owner contains two adjacent initialized P-256 x coordinates
    //   and is wiped exactly once on every exit.
    // - Each mutable span is disjoint and bounded to 32 bytes. The combined
    //   immutable borrow begins only after both writes complete.
    // - Storage is bound only to UInt8; no pointer escapes or crosses Sendable.
    var shared = SIMD64<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) { rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        let pointer = bytes.baseAddress.unsafelyUnwrapped
        var firstDestination = MutableSpan(
          _unsafeStart: pointer,
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: firstPrivateKey,
          peerPublicKey: firstPeerPublicKey,
          into: &firstDestination
        )
        var secondDestination = MutableSpan(
          _unsafeStart: pointer.advanced(by: P256KeyAgreement.sharedSecretByteCount),
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: secondPrivateKey,
          peerPublicKey: secondPeerPublicKey,
          into: &secondDestination
        )
      }
    } catch let error {
      throw .primitive(error)
    }
    return try withUnsafeBytes(of: &shared) { rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
    }
  }

  private static func withAuthenticatedDecapsulatedSharedSecrets<Result: ~Copyable>(
    firstPrivateKey: borrowing P256PrivateKey,
    firstPeerPublicKeyBytes: Span<UInt8>,
    secondPrivateKey: borrowing P256PrivateKey,
    secondPeerPublicKey: borrowing P256PublicKey,
    _ body: (Span<UInt8>) throws(HPKEError) -> Result
  ) throws(HPKEError) -> Result {
    // Unsafe boundary invariants:
    // - The SIMD owner contains two adjacent initialized P-256 x coordinates
    //   and is wiped exactly once on every exit.
    // - Each mutable span is disjoint and bounded to 32 bytes. The first uses
    //   single-use decoding; the reusable authenticated key keeps its comb.
    // - Storage is bound only to UInt8; no pointer escapes or crosses Sendable.
    var shared = SIMD64<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &shared) { bytes in
        SecureWipe.erase(bytes.baseAddress.unsafelyUnwrapped, byteCount: bytes.count)
      }
    }
    do {
      try withUnsafeMutableBytes(of: &shared) { rawBytes throws(CryptoInputError) in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        let pointer = bytes.baseAddress.unsafelyUnwrapped
        var firstDestination = MutableSpan(
          _unsafeStart: pointer,
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: firstPrivateKey,
          peerPublicKeyBytes: firstPeerPublicKeyBytes,
          into: &firstDestination
        )
        var secondDestination = MutableSpan(
          _unsafeStart: pointer.advanced(by: P256KeyAgreement.sharedSecretByteCount),
          count: P256KeyAgreement.sharedSecretByteCount
        )
        try P256KeyAgreement.sharedSecret(
          privateKey: secondPrivateKey,
          peerPublicKey: secondPeerPublicKey,
          into: &secondDestination
        )
      }
    } catch {
      throw .invalidEncapsulation
    }
    return try withUnsafeBytes(of: &shared) { rawBytes throws(HPKEError) -> Result in
      try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
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
}
