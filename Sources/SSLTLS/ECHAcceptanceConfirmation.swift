import SSLCore
import SSLCrypto

/// RFC 9849 ServerHello acceptance confirmation for TLS 1.3.
internal enum ECHAcceptanceConfirmation {
  static let byteCount = 8

  static func compute(
    innerClientHello: Span<UInt8>,
    serverHello: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> OwnedBytes {
    guard serverHello.count >= 38,
      serverHello[0] == TLS13HandshakeCodec.serverHelloType
    else {
      throw .invalidClientHello
    }
    var modifiedServerHello = copy(serverHello)
    var index = 30
    while index < 38 {
      modifiedServerHello[index] = 0
      index += 1
    }
    let parsedInner: TLS13ClientHello
    do {
      parsedInner = try TLS13HandshakeCodec.parseClientHello(
        innerClientHello,
        encoding: handshakeEncoding
      )
    } catch {
      throw .invalidClientHello
    }
    let transcript = try makeTranscript(
      clientHello: innerClientHello,
      serverHello: modifiedServerHello.span
    )
    let transcriptHash: OwnedBytes
    do {
      transcriptHash = try transcript.digest(for: cipherSuite)
    } catch {
      throw .cryptographicFailure
    }
    return try derive(
      innerRandom: parsedInner.random.span,
      transcriptHash: transcriptHash.span,
      label: "tls13 ech accept confirmation",
      cipherSuite: cipherSuite
    )
  }

  static func computeHelloRetryRequest(
    innerClientHello: Span<UInt8>,
    helloRetryRequest: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> OwnedBytes {
    let parsedInner: TLS13ClientHello
    let parsedRetry: TLS13HelloRetryRequest
    do {
      parsedInner = try TLS13HandshakeCodec.parseClientHello(
        innerClientHello,
        encoding: handshakeEncoding
      )
      parsedRetry = try TLS13HandshakeCodec.parseHelloRetryRequest(
        helloRetryRequest,
        encoding: handshakeEncoding
      )
    } catch {
      throw .invalidClientHello
    }
    guard parsedRetry.cipherSuite == cipherSuite else {
      throw .invalidClientHello
    }
    let zeroConfirmation = ContiguousArray<UInt8>(
      repeating: 0,
      count: byteCount
    )
    let zeroRetry: OwnedBytes
    do {
      zeroRetry = try TLS13HandshakeCodec.makeHelloRetryRequest(
        cookie: parsedRetry.cookie.span,
        cipherSuite: cipherSuite,
        echAcceptanceConfirmation: zeroConfirmation.span,
        encoding: handshakeEncoding
      )
    } catch {
      throw .invalidClientHello
    }
    let transcriptHash: OwnedBytes
    do {
      var transcript = try TLS13Transcript()
      try transcript.append(innerClientHello)
      try transcript.replaceWithMessageHash(for: cipherSuite)
      try transcript.append(zeroRetry.span)
      transcriptHash = try transcript.digest(for: cipherSuite)
    } catch {
      throw .cryptographicFailure
    }
    return try derive(
      innerRandom: parsedInner.random.span,
      transcriptHash: transcriptHash.span,
      label: "tls13 hrr ech accept confirmation",
      cipherSuite: cipherSuite
    )
  }

  static func isHelloRetryRequestAccepted(
    innerClientHello: Span<UInt8>,
    helloRetryRequest: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> Bool {
    let parsed: TLS13HelloRetryRequest
    do {
      parsed = try TLS13HandshakeCodec.parseHelloRetryRequest(
        helloRetryRequest,
        encoding: handshakeEncoding
      )
    } catch {
      throw .invalidClientHello
    }
    guard let confirmation = parsed.echAcceptanceConfirmation else {
      return false
    }
    let expected = try computeHelloRetryRequest(
      innerClientHello: innerClientHello,
      helloRetryRequest: helloRetryRequest,
      cipherSuite: cipherSuite,
      handshakeEncoding: handshakeEncoding
    )
    return ConstantTime.equal(expected.span, confirmation.span)
  }

  private static func derive(
    innerRandom: Span<UInt8>,
    transcriptHash: Span<UInt8>,
    label: String,
    cipherSuite: TLSCipherSuite
  ) throws(ECHError) -> OwnedBytes {
    let hashByteCount = cipherSuite == .aes256GCM_SHA384 ? 48 : 32
    let zeroSalt = ContiguousArray<UInt8>(repeating: 0, count: hashByteCount)
    var pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0,
      count: hashByteCount
    )
    defer { wipe(&pseudorandomKey) }
    var output = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
    var info = ContiguousArray<UInt8>()
    let encodedLabel = ContiguousArray(label.utf8)
    info.reserveCapacity(2 + 1 + encodedLabel.count + 1 + transcriptHash.count)
    appendUInt16(UInt16(byteCount), to: &info)
    info.append(UInt8(encodedLabel.count))
    info.append(contentsOf: encodedLabel)
    info.append(UInt8(transcriptHash.count))
    append(transcriptHash, to: &info)
    do {
      var keyOutput = pseudorandomKey.mutableSpan
      var confirmationOutput = output.mutableSpan
      switch cipherSuite {
      case .aes256GCM_SHA384:
        try HKDFSHA384.extract(
          inputKeyMaterial: innerRandom,
          salt: zeroSalt.span,
          into: &keyOutput
        )
        try HKDFSHA384.expand(
          pseudorandomKey: pseudorandomKey.span,
          info: info.span,
          into: &confirmationOutput
        )
      case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
        try HKDFSHA256.extract(
          inputKeyMaterial: innerRandom,
          salt: zeroSalt.span,
          into: &keyOutput
        )
        try HKDFSHA256.expand(
          pseudorandomKey: pseudorandomKey.span,
          info: info.span,
          into: &confirmationOutput
        )
      }
    } catch {
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: output)
  }

  static func isAccepted(
    innerClientHello: Span<UInt8>,
    serverHello: Span<UInt8>,
    cipherSuite: TLSCipherSuite,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> Bool {
    guard serverHello.count >= 38 else { throw .invalidClientHello }
    let expected = try compute(
      innerClientHello: innerClientHello,
      serverHello: serverHello,
      cipherSuite: cipherSuite,
      handshakeEncoding: handshakeEncoding
    )
    return ConstantTime.equal(
      expected.span,
      serverHello.extracting(30..<38)
    )
  }

  private static func appendUInt16(
    _ value: UInt16,
    to bytes: inout ContiguousArray<UInt8>
  ) {
    bytes.append(UInt8(truncatingIfNeeded: value >> 8))
    bytes.append(UInt8(truncatingIfNeeded: value))
  }

  private static func makeTranscript(
    clientHello: Span<UInt8>,
    serverHello: Span<UInt8>
  ) throws(ECHError) -> TLS13Transcript {
    do {
      var transcript = try TLS13Transcript()
      try transcript.append(clientHello)
      try transcript.append(serverHello)
      return transcript
    } catch {
      throw .cryptographicFailure
    }
  }

  private static func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  private static func copy(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(source.count)
    append(source, to: &result)
    return result
  }

  private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBytes { raw in
      if let baseAddress = raw.baseAddress {
        SecureWipe.erase(baseAddress, byteCount: raw.count)
      }
    }
  }
}
