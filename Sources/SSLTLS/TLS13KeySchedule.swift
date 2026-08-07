import SSLCore
import SSLCrypto

/// RFC 8446 TLS 1.3 key schedule for the supported SHA-256/SHA-384 suites.
public struct TLS13KeySchedule: ~Copyable, Sendable {
  public let cipherSuite: TLSCipherSuite
  private let earlySecret: SecretBytes

  public init(
    cipherSuite: TLSCipherSuite,
    preSharedKey: Span<UInt8>
  ) throws(TLS13KeyScheduleError) {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    guard preSharedKey.count <= 64 * 1024 else {
      throw .invalidPreSharedKeyLength(actual: preSharedKey.count)
    }
    let zeroSalt = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
    let early: SecretBytes
    if preSharedKey.isEmpty {
      // RFC 8446 section 7.1 defines the absent-PSK input as a string of
      // Hash.length zero bytes. A zero-length HKDF input produces a different
      // early secret and breaks interoperability with conforming TLS stacks.
      let absentPSK = ContiguousArray<UInt8>(
        repeating: 0,
        count: hashByteCount
      )
      early = try Self.extract(
        salt: zeroSalt.span,
        inputKeyMaterial: absentPSK.span,
        cipherSuite: cipherSuite
      )
    } else {
      early = try Self.extract(
        salt: zeroSalt.span,
        inputKeyMaterial: preSharedKey,
        cipherSuite: cipherSuite
      )
    }
    self.cipherSuite = cipherSuite
    earlySecret = early
  }

  public borrowing func makeHandshakeSecrets(
    ecdheSharedSecret: Span<UInt8>,
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> TLS13HandshakeSecrets {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    let isSupportedSecretLength =
      ecdheSharedSecret.count
      == TLS13NamedGroup.x25519.sharedSecretByteCount
      || ecdheSharedSecret.count
        == TLS13NamedGroup.x25519MLKEM768.sharedSecretByteCount
    guard isSupportedSecretLength else {
      throw .invalidECDHESecretLength(actual: ecdheSharedSecret.count)
    }
    guard transcriptHash.count == hashByteCount else {
      throw .invalidTranscriptHashLength(
        expected: hashByteCount, actual: transcriptHash.count)
    }

    let emptyHash = try Self.hashEmptyMessage(cipherSuite: cipherSuite)
    let derivedEarly = try Self.deriveSecret(
      secret: earlySecret,
      label: "derived",
      transcriptHash: emptyHash.span,
      cipherSuite: cipherSuite
    )
    let handshakeSecret = try Self.extract(
      salt: derivedEarly,
      inputKeyMaterial: ecdheSharedSecret,
      cipherSuite: cipherSuite
    )
    let client = try Self.deriveSecret(
      secret: handshakeSecret,
      label: "c hs traffic",
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
    let server = try Self.deriveSecret(
      secret: handshakeSecret,
      label: "s hs traffic",
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
    let derivedHandshake = try Self.deriveSecret(
      secret: handshakeSecret,
      label: "derived",
      transcriptHash: emptyHash.span,
      cipherSuite: cipherSuite
    )
    let zeroInput = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
    let master = try Self.extract(
      salt: derivedHandshake,
      inputKeyMaterial: zeroInput.span,
      cipherSuite: cipherSuite
    )
    return TLS13HandshakeSecrets(
      cipherSuite: cipherSuite,
      clientTrafficSecret: client,
      serverTrafficSecret: server,
      masterSecret: master
    )
  }

  /// Derives the client-to-server 0-RTT traffic secret from the complete
  /// ClientHello transcript hash.
  public borrowing func makeClientEarlyTrafficSecret(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> TLS13EarlyTrafficSecret {
    let secret = try Self.deriveSecret(
      secret: earlySecret,
      label: "c e traffic",
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
    return TLS13EarlyTrafficSecret(
      cipherSuite: cipherSuite,
      secret: secret
    )
  }

  static func hashByteCount(for suite: TLSCipherSuite) -> Int {
    suite == .aes256GCM_SHA384 ? 48 : 32
  }

  static func deriveSecret(
    secret: borrowing SecretBytes,
    label: String,
    transcriptHash: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    guard transcriptHash.count == hashByteCount else {
      throw .invalidTranscriptHashLength(
        expected: hashByteCount, actual: transcriptHash.count)
    }
    return try Self.expandLabel(
      secret: secret,
      label: label,
      context: transcriptHash,
      outputByteCount: hashByteCount,
      cipherSuite: cipherSuite
    )
  }

  /// Derives the next sending or receiving traffic secret from RFC 8446
  /// section 7.2. The update label has an empty context, unlike
  /// `Derive-Secret`, which hashes a transcript before expanding.
  static func updateTrafficSecret(
    secret: borrowing SecretBytes,
    cipherSuite: TLSCipherSuite,
    label: String = "traffic upd"
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    return try Self.expandLabel(
      secret: secret,
      label: label,
      context: emptyBytes.span,
      outputByteCount: hashByteCount,
      cipherSuite: cipherSuite
    )
  }

  static func deriveResumptionPSK(
    resumptionMasterSecret: borrowing SecretBytes,
    ticketNonce: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    return try Self.expandLabel(
      secret: resumptionMasterSecret,
      label: "resumption",
      context: ticketNonce,
      outputByteCount: hashByteCount,
      cipherSuite: cipherSuite
    )
  }

  static func deriveResumptionBinderKey(
    preSharedKey: borrowing SecretBytes,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    let zeroSalt = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
    let earlySecret: SecretBytes
    do {
      earlySecret = try preSharedKey.withBorrowedBytes { key in
        try Self.extract(
          salt: zeroSalt.span,
          inputKeyMaterial: key,
          cipherSuite: cipherSuite
        )
      }
    } catch {
      throw .cryptographicFailure
    }
    let emptyHash = try Self.hashEmptyMessage(cipherSuite: cipherSuite)
    return try Self.deriveSecret(
      secret: earlySecret,
      label: "res binder",
      transcriptHash: emptyHash.span,
      cipherSuite: cipherSuite
    )
  }

  static func finishedVerifyData(
    trafficSecret: borrowing SecretBytes,
    transcriptHash: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    let hashByteCount = Self.hashByteCount(for: cipherSuite)
    let finishedKey = try Self.expandLabel(
      secret: trafficSecret,
      label: "finished",
      context: emptyBytes.span,
      outputByteCount: hashByteCount,
      cipherSuite: cipherSuite
    )
    guard transcriptHash.count == hashByteCount else {
      throw .invalidTranscriptHashLength(
        expected: hashByteCount, actual: transcriptHash.count)
    }
    var output = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
    let outputByteCount = output.count
    do {
      try finishedKey.withBorrowedBytes { key in
        try output.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
          var destination = MutableSpan(
            _unsafeStart: buffer.baseAddress!, count: outputByteCount)
          switch cipherSuite {
          case .aes256GCM_SHA384:
            try HMACSHA384.authenticate(transcriptHash, using: key, into: &destination)
          case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
            try HMACSHA256.authenticate(transcriptHash, using: key, into: &destination)
          }
        }
      }
    } catch {
      wipe(&output)
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: output)
  }

  /// Implements RFC 8446 HKDF-Expand-Label with the caller-supplied raw
  /// context. Callers implementing Derive-Secret must pass a transcript hash;
  /// Finished, traffic updates, and resumption pass their specified raw context.
  static func expandLabel(
    secret: borrowing SecretBytes,
    label: String,
    context: Span<UInt8>,
    outputByteCount: Int,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let fullLabelByteCount = 6 + label.utf8.count
    guard outputByteCount > 0, outputByteCount <= UInt16.max else {
      throw .invalidOutputLength(actual: outputByteCount)
    }
    guard fullLabelByteCount <= UInt8.max, context.count <= UInt8.max else {
      throw .cryptographicFailure
    }
    var info = ContiguousArray<UInt8>()
    info.reserveCapacity(2 + 1 + fullLabelByteCount + 1 + context.count)
    info.append(UInt8(truncatingIfNeeded: outputByteCount >> 8))
    info.append(UInt8(truncatingIfNeeded: outputByteCount))
    info.append(UInt8(fullLabelByteCount))
    info.append(contentsOf: "tls13 ".utf8)
    info.append(contentsOf: label.utf8)
    info.append(UInt8(context.count))
    var contextIndex = 0
    while contextIndex < context.count {
      info.append(context[contextIndex])
      contextIndex += 1
    }
    return try Self.expand(
      secret: secret,
      info: info.span,
      outputByteCount: outputByteCount,
      cipherSuite: cipherSuite
    )
  }

  private static func expand(
    secret: borrowing SecretBytes,
    info: Span<UInt8>,
    outputByteCount: Int,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let secretByteCount: SecretByteCount
    do {
      secretByteCount = try SecretByteCount(outputByteCount)
    } catch {
      throw .invalidSecretMemory
    }
    do {
      return try SecretBytes(byteCount: secretByteCount) { destination throws(HKDFError) in
        try secret.withBorrowedBytes { secretBytes throws(HKDFError) in
          switch cipherSuite {
          case .aes256GCM_SHA384:
            try HKDFSHA384.expand(
              pseudorandomKey: secretBytes,
              info: info,
              into: &destination
            )
          case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
            try HKDFSHA256.expand(
              pseudorandomKey: secretBytes,
              info: info,
              into: &destination
            )
          }
        }
      }
    } catch let error {
      throw .hkdfFailure(error)
    }
  }

  private static func extract(
    salt: Span<UInt8>,
    inputKeyMaterial: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let outputByteCount = Self.hashByteCount(for: cipherSuite)
    let secretByteCount: SecretByteCount
    do {
      secretByteCount = try SecretByteCount(outputByteCount)
    } catch {
      throw .invalidSecretMemory
    }
    do {
      return try SecretBytes(byteCount: secretByteCount) { destination throws(HKDFError) in
        switch cipherSuite {
        case .aes256GCM_SHA384:
          try HKDFSHA384.extract(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            into: &destination
          )
        case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
          try HKDFSHA256.extract(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            into: &destination
          )
        }
      }
    } catch let error {
      throw .hkdfFailure(error)
    }
  }

  private static func extract(
    salt: borrowing SecretBytes,
    inputKeyMaterial: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let outputByteCount = Self.hashByteCount(for: cipherSuite)
    let secretByteCount: SecretByteCount
    do {
      secretByteCount = try SecretByteCount(outputByteCount)
    } catch {
      throw .invalidSecretMemory
    }
    do {
      return try SecretBytes(byteCount: secretByteCount) { destination throws(HKDFError) in
        try salt.withBorrowedBytes { saltBytes throws(HKDFError) in
          switch cipherSuite {
          case .aes256GCM_SHA384:
            try HKDFSHA384.extract(
              inputKeyMaterial: inputKeyMaterial,
              salt: saltBytes,
              into: &destination
            )
          case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
            try HKDFSHA256.extract(
              inputKeyMaterial: inputKeyMaterial,
              salt: saltBytes,
              into: &destination
            )
          }
        }
      }
    } catch let error {
      throw .hkdfFailure(error)
    }
  }

  static func hashEmptyMessage(
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    let outputByteCount = Self.hashByteCount(for: cipherSuite)
    var output = ContiguousArray<UInt8>(repeating: 0, count: outputByteCount)
    let emptyInput = ContiguousArray<UInt8>()
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) in
        let baseAddress = buffer.baseAddress!
        var destination = MutableSpan(_unsafeStart: baseAddress, count: outputByteCount)
        switch cipherSuite {
        case .aes256GCM_SHA384:
          try SHA384.hash(emptyInput.span, into: &destination)
        case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
          try SHA256.hash(emptyInput.span, into: &destination)
        }
      }
    } catch {
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: output)
  }

  private static let emptyBytes = ContiguousArray<UInt8>()

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }
}
