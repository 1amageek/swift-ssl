import SSL
import SSLASN1
import SSLCore
import SSLCrypto
import SSLQUIC
import SSLTLS
import SSLX509

@main
enum TargetValidationCommand {
  enum Failure: Error {
    case aesGCM
    case chacha20Poly1305
    case x25519
    case hybridKeyExchange
    case tlsP256KeyExchange
    case hpke
    case ech
    case p256
    case nistECDSA
    case rsaPSS
    case signingKeyImport
    case rsaPKCS1v15
    case hmacDRBG
    case sha384512
    case sha3
    case byteCursor
    case derCursor
    case entropy
    case secretOwner
    case sha256
    case hmacSHA256
    case hkdfSHA256
    case actionBatch
    case quicSecret
    case quicStepOutput
    case profileBoundary
    case uint24Failure
    case dtlsReplay
    case dtlsSRTP
    case quicInitial
    case quicCryptoStream
    case tlsClientAuthentication
    case tlsEarlyData
  }

  private struct FixedEntropy: EntropySource {
    let bytes: ContiguousArray<UInt8>

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
      guard destination.count == bytes.count else {
        throw .partialFill(expected: destination.count, actual: bytes.count)
      }
      var index = 0
      while index < bytes.count {
        destination[index] = bytes[index]
        index += 1
      }
    }
  }

  static func main() throws {
    try validateSystemEntropy()
    try validateAESGCM()
    try validateChaCha20Poly1305()
    try validateX25519()
    try validateHybridKeyExchange()
    try validateTLSP256KeyExchange()
    try validateHPKE()
    try validateP256HPKE()
    try validateECH()
    try validateP256()
    try validateRSAPSS()
    try validateSigningKeyImport()
    try validateRSAPKCS1v15()
    try validateHMACDRBG()
    try validateSHA384AndSHA512()
    try validateSHA3()
    try validateSHA256()
    try validateHMACSHA256()
    try validateHKDFSHA256()
    try validateActionBatch()
    try validateByteCursor()
    try validateDERCursor()
    try validateProfiles()
    try validateQUICSecretEvent()
    try validateQUICStepOutput()
    try validateSecretOwner()
    try validateUInt24Failure()
    try validateDTLSReplay()
    try validateDTLSSRTP()
    try validateQUICInitial()
    try validateQUICCryptoStream()
    try validateTLSEarlyData()
    try validateTLSClientAuthentication()
    print("swift-ssl target validation: ok")
  }

  private static func validateSystemEntropy() throws {
    var bytes = ContiguousArray<UInt8>(repeating: 0, count: 64)
    var destination = bytes.mutableSpan
    try SystemEntropySource().fill(&destination)
    var combined: UInt8 = 0
    var index = 0
    while index < bytes.count {
      combined |= bytes[index]
      index += 1
    }
    guard combined != 0 else { throw Failure.entropy }
  }

  private static func validateAESGCM() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 16)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>(repeating: 0, count: 16)
    let authenticatedData = ContiguousArray<UInt8>()
    let expected: ContiguousArray<UInt8> = [
      0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
      0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
      0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
      0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    let cipher = try SSL.AESGCM(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span,
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else {
      throw Failure.aesGCM
    }

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: authenticatedData.span,
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else {
      throw Failure.aesGCM
    }
  }

  private static func validateDTLSReplay() throws {
    var window = DTLS13ReplayWindow()
    guard try window.accept(10) == .accepted,
      try window.accept(9) == .accepted,
      try window.accept(10) == .replayed
    else {
      throw Failure.dtlsReplay
    }
  }

  private static func validateDTLSSRTP() throws {
    let zeroPSK = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let sharedSecret = try hexadecimalBytes(
      "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    )
    let helloTranscriptHash = try hexadecimalBytes(
      "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    )
    let applicationTranscriptHash = try hexadecimalBytes(
      "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
    )
    let schedule = try TLS13KeySchedule(
      cipherSuite: .aes128GCM_SHA256,
      preSharedKey: zeroPSK.span
    )
    let handshake = try schedule.makeHandshakeSecrets(
      ecdheSharedSecret: sharedSecret.span,
      transcriptHash: helloTranscriptHash.span
    )
    let application = try handshake.makeApplicationSecrets(
      transcriptHash: applicationTranscriptHash.span
    )
    let exported = try application.exportKeyingMaterial(
      label: "EXTRACTOR-dtls_srtp",
      context: Span<UInt8>(),
      outputByteCount: DTLSSRTPProtectionProfile.aeadAES256GCM.exporterByteCount
    )
    let expected = try hexadecimalBytes(
      "0e30a85a5b29a641bc75ca72910008b1b8236c3247fd404f89f347b815ce576c"
        + "9afeb1dde16f00090819e0fe58fd49bee1f1a36de5bd6250e1ab4f04d612819d"
        + "07ac0a605c3066e12c13cdc36002fdcce168b7fc660c5ef9"
    )
    guard exported.withBorrowedBytes({ ConstantTime.equal($0, expected.span) }) else {
      throw Failure.dtlsSRTP
    }

    let identifier: ContiguousArray<UInt8> = [1, 2, 3]
    let useSRTP = DTLSSRTPUseSRTPData(
      protectionProfiles: [.aeadAES128GCM, .aeadAES256GCM],
      masterKeyIdentifier: OwnedBytes(copying: identifier.span)
    )
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
      useSRTP: useSRTP,
      encoding: .dtls13
    )
    let parsed = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span,
      encoding: .dtls13
    )
    guard parsed.useSRTP == useSRTP else {
      throw Failure.dtlsSRTP
    }
  }

  private static func validateQUICInitial() throws {
    let connectionID = ContiguousArray<UInt8>([
      0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ])
    let secrets = try QUICInitialSecrets(destinationConnectionID: connectionID.span)
    let expected = ContiguousArray<UInt8>([
      0x1F, 0x36, 0x96, 0x13, 0xDD, 0x76, 0xD5, 0x46,
      0x77, 0x30, 0xEF, 0xCB, 0xE3, 0xB1, 0xA2, 0x2D,
    ])
    guard secrets.withClientKey({ key in copy(key) }) == expected else {
      throw Failure.quicInitial
    }
  }

  private static func validateQUICCryptoStream() throws {
    var stream = try QUICCryptoStreamReassembler(
      encryptionLevel: .handshake,
      maximumBufferedByteCount: 8
    )
    let tail: ContiguousArray<UInt8> = [3, 4]
    let head: ContiguousArray<UInt8> = [1, 2]
    try stream.receive(offset: 2, bytes: tail.span)
    try stream.receive(offset: 0, bytes: head.span)
    guard stream.withContiguousBytes({ copy($0) }) == [1, 2, 3, 4] else {
      throw Failure.quicCryptoStream
    }
    try stream.discardContiguousBytes(count: 3)

    let wrapped: ContiguousArray<UInt8> = [5, 6, 7, 8, 9, 10, 11]
    try stream.receive(offset: 4, bytes: wrapped.span)
    guard stream.withContiguousBytes({ copy($0) }) == [4, 5, 6, 7, 8, 9, 10, 11] else {
      throw Failure.quicCryptoStream
    }

    let conflict: ContiguousArray<UInt8> = [0]
    do {
      try stream.receive(offset: 7, bytes: conflict.span)
      throw Failure.quicCryptoStream
    } catch let error as QUICCryptoStreamError {
      guard error == .conflictingOverlap(offset: 7) else {
        throw Failure.quicCryptoStream
      }
    }
  }

  private static func validateTLSEarlyData() throws {
    let ticketNonce: ContiguousArray<UInt8> = [1, 2, 3]
    let ticket: ContiguousArray<UInt8> = [0xA0, 0xB0, 0xC0]
    let encodedTicket = try TLS13SessionTicketCodec.makeNewSessionTicket(
      lifetime: 3_600,
      ageAdd: 7,
      ticketNonce: ticketNonce.span,
      ticket: ticket.span,
      maximumEarlyDataByteCount: 4_096
    )
    let parsedTicket = try TLS13SessionTicketCodec.parseNewSessionTicket(
      encodedTicket.span
    )
    guard parsedTicket.maximumEarlyDataByteCount == 4_096 else {
      throw Failure.tlsEarlyData
    }

    let preSharedKey = ContiguousArray<UInt8>(repeating: 0x55, count: 32)
    var clientHelloTranscriptHash = ContiguousArray<UInt8>(
      repeating: 0,
      count: SSLCrypto.SHA256.digestByteCount
    )
    var clientHelloTranscriptHashSpan = clientHelloTranscriptHash.mutableSpan
    try SSLCrypto.SHA256.hash(
      ticket.span,
      into: &clientHelloTranscriptHashSpan
    )
    let schedule = try TLS13KeySchedule(
      cipherSuite: .aes128GCM_SHA256,
      preSharedKey: preSharedKey.span
    )
    let secret = try schedule.makeClientEarlyTrafficSecret(
      transcriptHash: clientHelloTranscriptHash.span
    )
    let secretBytes = secret.withBorrowedSecret { copy($0) }
    guard secretBytes.count == 32,
      secretBytes.contains(where: { $0 != 0 })
    else {
      throw Failure.tlsEarlyData
    }
  }

  private static func validateTLSClientAuthentication() throws {
    let seed: ContiguousArray<UInt8> = [
      0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60,
      0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C, 0xC4,
      0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19,
      0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE, 0x7F, 0x60,
    ]
    let certificateDER: ContiguousArray<UInt8> = [
      0x30, 0x81, 0xA6, 0x30, 0x5A, 0x02, 0x01, 0x01,
      0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30,
      0x00, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x34, 0x30,
      0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x5A, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31,
      0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x5A, 0x30, 0x00, 0x30, 0x2A, 0x30, 0x05, 0x06,
      0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0xD7,
      0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5,
      0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A, 0x0E,
      0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF,
      0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A, 0x30,
      0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41,
      0x00, 0x37, 0xDF, 0xBF, 0x24, 0xEB, 0x69, 0x2E,
      0x0B, 0xE9, 0x24, 0x3A, 0x10, 0xE9, 0x0E, 0x7A,
      0x42, 0x05, 0x28, 0xF6, 0xDC, 0xD6, 0x03, 0x28,
      0x98, 0xDC, 0xA9, 0x56, 0xD5, 0x1C, 0xE3, 0xA2,
      0x86, 0xB1, 0x55, 0x96, 0x38, 0x08, 0x32, 0xA6,
      0x0C, 0xC5, 0x7D, 0x2A, 0x84, 0xF8, 0x43, 0xC7,
      0x74, 0xFF, 0xE0, 0xA7, 0xB4, 0x62, 0xA9, 0x55,
      0x6F, 0x76, 0x75, 0x1A, 0x87, 0x0D, 0x5C, 0x79,
      0x01,
    ]
    let certificate = try X509Certificate(der: certificateDER.span)
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let identity = try TLS13ClientIdentity(
      certificateEntries: [
        try TLS13CertificateEntry(certificateDER: certificateDER.span)
      ],
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: seed.span)
      ),
      verificationInstant: instant
    )
    var client = try TLS13ClientHandshake(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x11, count: 32).span
      ),
      certificateValidator: try RFC5280TLS13ServerCertificateValidator(
        trustAnchors: [certificate]
      ),
      clientIdentity: identity,
      verificationInstant: instant
    )
    var server = try TLS13ServerHandshake(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: X25519PrivateKey(
        bytes: ContiguousArray(repeating: 0x22, count: 32).span
      ),
      certificateDER: certificateDER.span,
      signingKey: TLS13SigningKey(
        ed25519: try Ed25519PrivateKey(seed: seed.span)
      ),
      verificationInstant: instant,
      clientAuthentication: TLS13ClientAuthenticationConfiguration(
        requirement: .required,
        validator: try RFC5280TLS13ClientCertificateValidator(
          trustAnchors: [certificate]
        )
      )
    )

    let clientHello = try client.start()
    let serverFlight = try server.receive(clientHello.bytes.span)
    let clientFinalFlight = try client.receive(serverFlight.bytes.span)
    _ = try server.receive(clientFinalFlight.bytes.span)
    guard client.isEstablished,
      server.isEstablished,
      server.authenticatedClientIdentity != nil
    else {
      throw Failure.tlsClientAuthentication
    }
  }

  private static func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private static func validateChaCha20Poly1305() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>()
    let expected: ContiguousArray<UInt8> = [
      0x4E, 0xB9, 0x72, 0xC9, 0xA8, 0xFB, 0x3A, 0x1B,
      0x38, 0x2B, 0xB4, 0xD3, 0x6F, 0x5F, 0xFA, 0xD1,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    let cipher = try SSL.ChaCha20Poly1305(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else { throw Failure.chacha20Poly1305 }

    var recovered = ContiguousArray<UInt8>()
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else { throw Failure.chacha20Poly1305 }
  }

  private static func validateX25519() throws {
    let alicePrivate = ContiguousArray<UInt8>([
      0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
      0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
      0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
      0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A,
    ])
    let bobPrivate = ContiguousArray<UInt8>(0..<32)
    let expectedPublic = ContiguousArray<UInt8>([
      0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54,
      0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
      0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4,
      0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
    ])
    let expectedShared = ContiguousArray<UInt8>([
      0x5B, 0xF2, 0x20, 0xD6, 0x70, 0xC9, 0x4B, 0x8D,
      0x70, 0xBC, 0x5E, 0xDE, 0x1C, 0xFF, 0xB8, 0x5D,
      0x6C, 0x4B, 0x7C, 0x9D, 0x87, 0x17, 0xBB, 0xB5,
      0xEB, 0x90, 0xC0, 0x25, 0x83, 0x86, 0x20, 0x07,
    ])
    let alice = try SSL.X25519PrivateKey(bytes: alicePrivate.span)
    let bob = try SSL.X25519PrivateKey(bytes: bobPrivate.span)
    let publicKey = alice.publicKey()
    guard publicKey.span.count == expectedPublic.count else {
      throw Failure.x25519
    }
    var index = 0
    while index < expectedPublic.count {
      guard publicKey.span[index] == expectedPublic[index] else {
        throw Failure.x25519
      }
      index += 1
    }
    let shared = try SSL.X25519.sharedSecret(
      privateKey: alice,
      peerPublicKey: bob.publicKey()
    )
    let matches = shared.withBorrowedBytes { bytes in
      guard bytes.count == expectedShared.count else { return false }
      var index = 0
      while index < bytes.count {
        if bytes[index] != expectedShared[index] { return false }
        index += 1
      }
      return true
    }
    guard matches else { throw Failure.x25519 }
  }

  private static func validateECH() throws {
    let scalar = ContiguousArray<UInt8>(repeating: 0x41, count: 32)
    let configKey = try SSLCrypto.X25519PrivateKey(bytes: scalar.span)
    let config = try ECHConfig(
      configID: 17,
      publicKey: configKey.publicKey().span,
      cipherSuites: [ECHCipherSuite(kdf: .sha256, aead: .aes128GCM)],
      maximumNameLength: 64,
      publicName: ContiguousArray("public.example".utf8).span
    )
    let list = try ECHConfigList(configurations: [config])
    let selected = try ECHX25519ConfigurationSelector().selectConfiguration(from: list)
    var sealer = try RFC9849ECHClientHelloSealer(
      selectedConfiguration: selected,
      using: FixedEntropy(bytes: ContiguousArray(repeating: 0x53, count: 32))
    )
    let keyShare = ContiguousArray<UInt8>(repeating: 0x31, count: 32)
    let inner = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyShare: keyShare.span,
      serverName: OwnedBytes(copying: ContiguousArray("origin.example".utf8).span)
    )
    let outer = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x22, count: 32).span,
      keyShare: keyShare.span,
      serverName: OwnedBytes(copying: ContiguousArray("public.example".utf8).span)
    )
    let offer = try sealer.seal(
      innerClientHello: inner.span,
      outerClientHello: outer.span
    )
    let serverConfiguration = try ECHServerConfiguration(
      config: config,
      privateKey: SSLCrypto.X25519PrivateKey(bytes: scalar.span)
    )
    var opener = try RFC9849ECHClientHelloOpener(configuration: serverConfiguration)
    let opened = try opener.open(offer.outerClientHello.span)
    let parsedInner = try TLS13HandshakeCodec.parseClientHello(opened.innerClientHello.span)
    let parsedOuter = try TLS13HandshakeCodec.parseClientHello(offer.outerClientHello.span)
    guard
      parsedInner.serverName == OwnedBytes(copying: ContiguousArray("origin.example".utf8).span),
      parsedOuter.serverName == OwnedBytes(copying: ContiguousArray("public.example".utf8).span)
    else {
      throw Failure.ech
    }

    var mutated = copy(offer.outerClientHello.span)
    mutated[mutated.count - 1] ^= 1
    let rejectionConfiguration = try ECHServerConfiguration(
      config: config,
      privateKey: SSLCrypto.X25519PrivateKey(bytes: scalar.span)
    )
    var rejectingOpener = try RFC9849ECHClientHelloOpener(
      configuration: rejectionConfiguration
    )
    do {
      _ = try rejectingOpener.open(mutated.span)
      throw Failure.ech
    } catch let error as ECHError {
      guard error == .payloadAuthenticationFailed else {
        throw Failure.ech
      }
    }
  }

  private static func validateHybridKeyExchange() throws {
    var client = try TLS13X25519MLKEM768ClientKeyExchange.generate(
      mlkemEntropy: FixedEntropy(bytes: sequential(count: 64, seed: 0x10)),
      x25519Entropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x30))
    )
    var server = try TLS13X25519MLKEM768ServerKeyExchange.generate(
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
    )
    let clientShare = client.withClientShare { OwnedBytes(copying: $0) }
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      namedGroup: .x25519MLKEM768,
      keyShare: clientShare.span
    )
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(clientHello.span)
    guard parsedClientHello.namedGroup == .x25519MLKEM768,
      parsedClientHello.keyShare.count == 1_216
    else {
      throw Failure.hybridKeyExchange
    }

    let serverResult = try server.accept(
      clientShare: parsedClientHello.keyShare.span,
      using: FixedEntropy(bytes: sequential(count: 32, seed: 0x70))
    )
    let serverHello = try TLS13HandshakeCodec.makeServerHello(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      namedGroup: .x25519MLKEM768,
      keyShare: serverResult.serverShare.span
    )
    let parsedServerHello = try TLS13HandshakeCodec.parseServerHello(serverHello.span)
    guard parsedServerHello.namedGroup == .x25519MLKEM768,
      parsedServerHello.keyShare.count == 1_120
    else {
      throw Failure.hybridKeyExchange
    }
    let clientSecret = try client.complete(serverShare: parsedServerHello.keyShare.span)
    let clientSecretBytes = clientSecret.withBorrowedBytes { copy($0) }
    let serverSecretBytes = serverResult.sharedSecret.withBorrowedBytes { copy($0) }
    guard clientSecretBytes.count == 64,
      clientSecretBytes == serverSecretBytes
    else {
      throw Failure.hybridKeyExchange
    }
  }

  private static func validateTLSP256KeyExchange() throws {
    var client = try TLS13P256ClientKeyExchange.generate(
      using: FixedEntropy(
        bytes: ContiguousArray(repeating: 0x11, count: 32)
      )
    )
    var server = try TLS13P256ServerKeyExchange.generate(
      using: FixedEntropy(
        bytes: ContiguousArray(repeating: 0x22, count: 32)
      )
    )
    let clientShare = client.withClientShare { OwnedBytes(copying: $0) }
    guard client.namedGroup == .secp256r1,
      clientShare.count == 65,
      clientShare.span[0] == 0x04
    else {
      throw Failure.tlsP256KeyExchange
    }

    let serverResult = try server.accept(
      clientShare: clientShare.span,
      using: FixedEntropy(
        bytes: ContiguousArray(repeating: 0x33, count: 32)
      )
    )
    guard serverResult.serverShare.count == 65,
      serverResult.serverShare.span[0] == 0x04
    else {
      throw Failure.tlsP256KeyExchange
    }
    let clientSecret = try client.complete(
      serverShare: serverResult.serverShare.span
    )
    let clientSecretBytes = clientSecret.withBorrowedBytes { copy($0) }
    let serverSecretBytes = serverResult.sharedSecret.withBorrowedBytes { copy($0) }
    guard clientSecretBytes.count == 32,
      clientSecretBytes == serverSecretBytes
    else {
      throw Failure.tlsP256KeyExchange
    }
  }

  private static func sequential(count: Int, seed: UInt8) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(count)
    var index = 0
    while index < count {
      result.append(seed &+ UInt8(truncatingIfNeeded: index))
      index += 1
    }
    return result
  }

  private static func validateHPKE() throws {
    let recipientPrivate = SSLCrypto.X25519KeyPair(
      privateKey: try SSLCrypto.X25519PrivateKey(
        bytes: ContiguousArray<UInt8>([
          0x80, 0x57, 0x99, 0x1E, 0xEF, 0x8F, 0x1F, 0x1A,
          0xF1, 0x8F, 0x4A, 0x94, 0x91, 0xD1, 0x6A, 0x1C,
          0xE3, 0x33, 0xF6, 0x95, 0xD4, 0xDB, 0x8E, 0x38,
          0xDA, 0x75, 0x97, 0x5C, 0x44, 0x78, 0xE0, 0xFB,
        ]).span))
    let info = ContiguousArray<UInt8>([
      0x4F, 0x64, 0x65, 0x20, 0x6F, 0x6E, 0x20, 0x61,
      0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61, 0x6E,
      0x20, 0x55, 0x72, 0x6E,
    ])
    let plaintext = ContiguousArray<UInt8>([
      0x42, 0x65, 0x61, 0x75, 0x74, 0x79, 0x20, 0x69,
      0x73, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x2C,
      0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x20, 0x62,
      0x65, 0x61, 0x75, 0x74, 0x79,
    ])
    let aad = ContiguousArray<UInt8>([0x43, 0x6F, 0x75, 0x6E, 0x74, 0x2D, 0x30])
    let secondPlaintext = ContiguousArray<UInt8>([0x53, 0x65, 0x71, 0x75, 0x65, 0x6E, 0x63, 0x65])
    let secondAAD = ContiguousArray<UInt8>([0x43, 0x6F, 0x75, 0x6E, 0x74, 0x2D, 0x31])
    let aeads: [HPKEAEAD] = [.aes128GCM, .aes256GCM, .chaCha20Poly1305]

    for aead in aeads {
      let entropy = FixedEntropy(
        bytes: ContiguousArray<UInt8>([
          0xF4, 0xEC, 0x9B, 0x33, 0xB7, 0x92, 0xC3, 0x72,
          0xC1, 0xD2, 0xC2, 0x06, 0x35, 0x07, 0xB6, 0x84,
          0xEF, 0x92, 0x5B, 0x8C, 0x75, 0xA4, 0x2D, 0xBC,
          0xBF, 0x57, 0xD6, 0x3C, 0xCD, 0x38, 0x16, 0x00,
        ]))
      var setup = try HPKEX25519.setupBaseSender(
        recipientPublicKey: recipientPrivate.publicKey,
        info: info.span,
        kdf: .sha256,
        aead: aead,
        using: entropy
      )
      var recipient = try HPKEX25519.setupBaseRecipient(
        encapsulation: setup.encapsulation.span,
        recipientKeyPair: recipientPrivate,
        info: info.span,
        kdf: .sha256,
        aead: aead
      )
      var sender = setup.takeContext()
      let ciphertext = try sender.seal(
        plaintext: plaintext.span,
        authenticatedData: aad.span
      )
      let opened = try recipient.open(
        ciphertext: ciphertext.span,
        authenticatedData: aad.span
      )
      let secondCiphertext = try sender.seal(
        plaintext: secondPlaintext.span,
        authenticatedData: secondAAD.span
      )
      let secondOpened = try recipient.open(
        ciphertext: secondCiphertext.span,
        authenticatedData: secondAAD.span
      )
      guard copy(opened.span) == plaintext,
        copy(secondOpened.span) == secondPlaintext,
        sender.sequenceNumber == 2,
        recipient.sequenceNumber == 2
      else {
        throw Failure.hpke
      }
    }
  }

  private static func validateP256HPKE() throws {
    let recipientScalar = try hexadecimalBytes(
      "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"
    )
    let recipient = SSLCrypto.P256KeyPair(
      privateKey: try SSLCrypto.P256PrivateKey(
        bytes: recipientScalar.span
      )
    )
    let info = try hexadecimalBytes("4f6465206f6e2061204772656369616e2055726e")
    let plaintext = try hexadecimalBytes(
      "4265617574792069732074727574682c20747275746820626561757479"
    )
    let authenticatedData = try hexadecimalBytes("436f756e742d30")
    let expectedEncapsulation = try hexadecimalBytes(
      "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac"
        + "98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
    )
    let expectedCiphertext = try hexadecimalBytes(
      "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f"
        + "9076ac232e3ab2523f39513434"
    )
    let entropy = FixedEntropy(
      bytes: try hexadecimalBytes(
        "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
      )
    )
    var setup = try SSLCrypto.HPKEP256.setupBaseSender(
      recipientPublicKey: recipient.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: entropy
    )
    guard copy(setup.encapsulation.span) == expectedEncapsulation else {
      throw Failure.hpke
    }
    var recipientContext = try SSLCrypto.HPKEP256.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientKeyPair: recipient,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var senderContext = setup.takeContext()
    let ciphertext = try senderContext.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span
    )
    guard copy(ciphertext.span) == expectedCiphertext else {
      throw Failure.hpke
    }
    let opened = try recipientContext.open(
      ciphertext: ciphertext.span,
      authenticatedData: authenticatedData.span
    )
    guard copy(opened.span) == plaintext else {
      throw Failure.hpke
    }
  }

  private static func validateP256() throws {
    let signingPublicKey = ContiguousArray<UInt8>([
      0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42,
      0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
      0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33,
      0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
      0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
      0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
      0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
      0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
      0xF5,
    ])
    let digest = ContiguousArray<UInt8>([
      0x17, 0x2B, 0x12, 0x96, 0xFE, 0xDD, 0xD5, 0xE2,
      0xC0, 0xB6, 0x30, 0x06, 0x15, 0x14, 0x2D, 0x3C,
      0x4F, 0x6D, 0x37, 0x5E, 0x5C, 0xB7, 0x0E, 0xD8,
      0xCF, 0xA9, 0x22, 0x0C, 0xCE, 0xB9, 0x4B, 0xE2,
    ])
    let rawSignature = ContiguousArray<UInt8>([
      0xB1, 0x86, 0x79, 0x69, 0x06, 0xE2, 0x66, 0x21,
      0xD8, 0x94, 0x0D, 0xDD, 0xF7, 0x93, 0x30, 0xF3,
      0x8F, 0xB9, 0xEB, 0x6D, 0x8D, 0x8D, 0x88, 0x23,
      0x6E, 0x72, 0x23, 0xC7, 0x11, 0x19, 0xC8, 0xCE,
      0xFA, 0x03, 0x75, 0x45, 0xB6, 0x06, 0xE0, 0x53,
      0xDB, 0xFB, 0x53, 0xAF, 0xF1, 0xD1, 0x82, 0x25,
      0x0E, 0x1C, 0xD6, 0xBE, 0xF8, 0xEF, 0x5B, 0x6F,
      0x56, 0xC3, 0x5C, 0x0B, 0x3E, 0xE8, 0xAF, 0x64,
    ])
    let signingKey = try SSL.P256PublicKey(bytes: signingPublicKey.span)
    let directSigningKey = try SSLCrypto.P256PublicKey(bytes: signingPublicKey.span)
    guard
      try SSLCrypto.P256ECDSA.verify(
        signature: rawSignature.span,
        messageHash: digest.span,
        using: directSigningKey
      )
    else {
      throw Failure.nistECDSA
    }
    guard
      try SSL.P256ECDSA.verify(
        signature: rawSignature.span,
        messageHash: digest.span,
        using: signingKey
      )
    else {
      throw Failure.nistECDSA
    }

    let privateScalar = try hexadecimalBytes(
      "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    )
    let signingDigest = try hexadecimalBytes(
      "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF"
    )
    let expectedSignature = try hexadecimalBytes(
      "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        + "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
    )
    let privateKey = try SSLCrypto.P256PrivateKey(
      bytes: privateScalar.span
    )
    let generatedSignature = try SSLCrypto.P256ECDSA.sign(
      messageHash: signingDigest.span,
      using: privateKey
    )
    guard generatedSignature == expectedSignature,
      try SSLCrypto.P256ECDSA.verify(
        signature: generatedSignature.span,
        messageHash: signingDigest.span,
        using: privateKey.publicKey()
      )
    else {
      throw Failure.nistECDSA
    }
  }

  private static func validateRSAPSS() throws {
    let modulus = try hexadecimalBytes(
      "B5E9172F65A2FB7D5D287F277A5CC182581497CF9FFC779839113DAD70B8EA9E"
        + "35EDB39C95C23ACC949B953132C0CDA4723C3E13E3FFBA97345FA8BA4947460B1"
        + "E833B4EC5793402CC19AFB3E9B3C406F9F423EE47C504C4E790314BE876EF4B0"
        + "68EF85C021349459A0E1B05B9E860864797AC588AB6F70EC55452915D0C3DDE9"
        + "9A0B4AA566F759A0BDA20080F96254512B4BDBFF4E0AAF68263B9BD513D16EBF"
        + "797D71BB8AA02611F544DB3C80F1EC5B60BD185D36ADBBDE988EBB9F6EE332E"
        + "7501F66A1413DD348D4F7F78D9F93172A029BAC6F4072EB81AF4CC9692D62153"
        + "04DD8C68F10F100925AD50987FC5D7FA1084532E90CED8F02A1BED6D92DE8A65"
    )
    let digest = try hexadecimalBytes(
      "29AEB90FADDF4D7ECE03FA92CFFB85213640FC5ED228181BD7BDE889FF3E7A5E"
    )
    let signature = try hexadecimalBytes(
      "6FA921CFAC77C99B35BFCD6722264EF9C4B508542AF7A517134938F75726E8E5B"
        + "696A019E709826339B0AA726B8FE02606D8F2DB94C345C9BC3112D97CAC3DF6E"
        + "166EDE61468C6D21A61FD573387F6770B3D13E44FD510FA9B9AABA6BB25C94EB"
        + "ED5E023FB4E531029DF7D35BD84AC5D34BAB24A349A537FCC1BAD294A6CD1E17"
        + "F917582603AF2468308C7E8E940A49B036ECED9791D9C593FA6B570B44ACC8B9"
        + "0EF80BCC69675FDE2BB1E3BDD9EA5F0461A87D5A8F427DB1ABFFE4443CFEFFFB"
        + "F13532C876975D9270E709E4D504457CBD124A5132DF4CEBF7E1B48A3BAF5E6C"
        + "BC3D4D7E27387204698250E1E7CD5C6DE8CF800DA203CD73D938FF911C1B5C4"
    )
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)
    guard
      try RSAPSS.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      )
    else {
      throw Failure.rsaPSS
    }

    var modifiedSignature = signature
    modifiedSignature[modifiedSignature.count - 1] ^= 1
    guard
      try !RSAPSS.verify(
        signature: modifiedSignature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      )
    else {
      throw Failure.rsaPSS
    }

    let signingModulus = try hexadecimalBytes(
      "daff26f7df96632c4d130150fc81d99f6d1913e98dd62dbe34d772e926602c94"
        + "e30c6839d6d60534b9e13c4ae0717aff5bea4978bc07f9372e1cf1fe59e44af1"
        + "95888d435b511564b3dbdebabf2b0ee7b8f9ef02c5379c7ca237ca32b32c6edc"
        + "1469e8a2943e079225f36820d96655817f14c27d0eb36007f6f7ccfc2c58adec"
        + "61d57cdb1481aca798529cd0bbae9dac029c43cf5c1e83236585670373aa9852f"
        + "226adc2697b266137b965d9954072938d3bb6d6c009dc228737b9cd1988e41835"
        + "82714973f2ba34a7159f24829000dbb6167c3edfd2899e73b7d20b6c3ef347e0"
        + "72fe2cfd458282ffc12ea537a7264f88b63480c3d5218d9ae9118ed2f4a361"
    )
    let privateExponent = try hexadecimalBytes(
      "30a2f82996cb948cf3352456b32db78253bd7d11a2c18d792fcd25a52833b5d2"
        + "ff35f333dd45bcf43fd0090eec17e7e42caab4d48e960ac0398a8e281a18bc98"
        + "38c891ef02a9d8617c1c79b3e9df0b396578849f8de352eacf302ac4e5cc1976"
        + "e145c037d34a8f6de2e5d31b708cecb28ce1b46c07c6c8ae1c285eab26c22f2"
        + "5e61fb39a663feae56fc905311ae0597dd985ceafa8e46cf811900b8b8a61547"
        + "bc4fa799098dcf9fa34dc3e71262496becf4438a3e3444f5eca8ee5102fe3ec3"
        + "c6839919f02b65b68a0c4140939cfd7d212f2a7a081cb93dc388c50d9f117240"
        + "f2c78e7e197bb31f09ea8d2d831929a954fc1f2d909e2ffca4948fe7565a3521d"
    )
    let privateKey = try RSAPrivateKey(
      modulus: signingModulus.span,
      publicExponent: 65_537,
      privateExponent: privateExponent.span
    )
    let signingPublicKey = privateKey.publicKey
    let generatedSignature = try RSAPSS.sign(
      messageHash: digest.span,
      using: privateKey,
      hash: .sha256,
      entropy: FixedEntropy(
        bytes: ContiguousArray(repeating: 0xA5, count: 32)
      )
    )
    guard
      try RSAPSS.verify(
        signature: generatedSignature.span,
        messageHash: digest.span,
        publicKey: signingPublicKey,
        hash: .sha256,
        saltLength: 32
      )
    else {
      throw Failure.rsaPSS
    }
  }

  private static func validateSigningKeyImport() throws {
    let privateKeyDER = try hexadecimalBytes(
      "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101"
        + "04200000000000000000000000000000000000000000000000000000000000000001"
    )
    let privateKeyInfo = try PrivateKeyInfo(der: privateKeyDER.span)
    let signingKey = try TLS13SigningKey(
      privateKeyInfo: consume privateKeyInfo
    )
    guard signingKey.signatureScheme == .ecdsaP256SHA256 else {
      throw Failure.signingKeyImport
    }
    _ = consume signingKey
  }

  private static func validateRSAPKCS1v15() throws {
    let modulus = try hexadecimalBytes(
      "F4F562EEF1868A943E858DB385112D5BF64E8E3EE9D671F1A6A2A5A131840EF1"
        + "38EB10E35C2D7DD76AE7F8B18C3881386265A03900D1E438D4747D3044447172"
        + "CAD6BC3C85D2F41AD63BAF84005857EB14658FBB93A4B3C9F633299E4DDEEEED"
        + "715C7A2B20B8C6FF97C5830AAF5361E1FDB97D219F32033264388D641344FFD2"
        + "28CEA97DA95C2CC8FD436532ACAB1BDEAB76DDFF5DD68D9CC473A0C84F3C4792"
        + "70F3299022C8ED8CEFB11BD1EBEBB8A4F27C959448CD8F0C9D3946E56D1D552"
        + "160BAC17DB2D7E1A2066A84CBAFBA5F07F707F24CBE11E536234E1A6BCD32CD1"
        + "04C0688AA508D3782076F9B9FEBCE621A10791C967B07785369FC665460C3B5A9"
    )
    let digest = try hexadecimalBytes(
      "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )
    let signature = try hexadecimalBytes(
      "5A99A2DE514F685BE33137296CBBD9AB30A0D56D46F98E89441333C69F0604B1"
        + "3658F0AA2F99E101897F8BE4E9A9B41150CCEAC7FE12CF1A8AE74F6C5D5AD322"
        + "164D9AA0B5F3F98F345782B253F02015166E0A290C99670D1FE5BDEF2DF0E646"
        + "43D4158DA48B3E504D1D309261CB9A3F70F5C4A357C553BFBA658596859A37658"
        + "7AB73802E1C910EC0A7B7B6597B2087227304BD417ECB44E85DCB03A53E89CC8"
        + "BAAADC88BD302274BA92877457856C3B16147A63D3EDA6A2627433088AAF1E22"
        + "C3AE6BF9CAD7761AA7376EBC1EBC5E4F22132D0B6490626CC3E6997951B6C4E"
        + "D301C47D6320147518B9F1B361FFB94A8204E80E9A9D98ACE21BB01834754A82"
    )
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)
    guard
      try RSAPKCS1v15.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256
      )
    else {
      throw Failure.rsaPKCS1v15
    }

    var modifiedSignature = signature
    modifiedSignature[modifiedSignature.count - 1] ^= 1
    guard
      try !RSAPKCS1v15.verify(
        signature: modifiedSignature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256
      )
    else {
      throw Failure.rsaPKCS1v15
    }
  }

  private static func validateHMACDRBG() throws {
    let entropy = FixedEntropy(bytes: ContiguousArray(0..<32))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    var generator = try HMACDRBG(
      entropy: entropy,
      nonce: nonce.span,
      personalization: personalization.span
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var outputSpan = output.mutableSpan
    try generator.generate(into: &outputSpan)
    let expected = ContiguousArray<UInt8>([
      0xAC, 0xB4, 0xC0, 0x52, 0x73, 0x46, 0x34, 0x3F,
      0x45, 0x26, 0x6A, 0x99, 0xA5, 0xEA, 0x86, 0xE9,
      0x49, 0x3B, 0x69, 0x63, 0x5F, 0x50, 0x9E, 0xD6,
      0x87, 0x1D, 0x4C, 0x87, 0x1F, 0x93, 0x61, 0x3B,
    ])
    guard output == expected else { throw Failure.hmacDRBG }
  }

  private static func validateSHA384AndSHA512() throws {
    let input = ContiguousArray("abc".utf8)
    let expected384 = ContiguousArray<UInt8>([
      0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
    ])
    let expected512 = ContiguousArray<UInt8>([
      0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
    ])
    var output384 = ContiguousArray<UInt8>(repeating: 0, count: SSL.SHA384.digestByteCount)
    var output384Span = output384.mutableSpan
    try SSL.SHA384.hash(input.span, into: &output384Span)
    var output512 = ContiguousArray<UInt8>(repeating: 0, count: SSL.SHA512.digestByteCount)
    var output512Span = output512.mutableSpan
    try SSL.SHA512.hash(input.span, into: &output512Span)
    guard output384 == expected384, output512 == expected512 else { throw Failure.sha384512 }
  }

  private static func validateSHA3() throws {
    var sha3 = ContiguousArray<UInt8>(repeating: 0, count: SSLCrypto.SHA3_256.digestByteCount)
    var sha3Span = sha3.mutableSpan
    try SSLCrypto.SHA3_256.hash(ContiguousArray<UInt8>().span, into: &sha3Span)
    let expected = ContiguousArray<UInt8>([
      0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
      0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
      0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA,
      0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A,
    ])
    guard sha3 == expected else { throw Failure.sha3 }

    var shake = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var shakeSpan = shake.mutableSpan
    try SSLCrypto.SHAKE128.hash(
      ContiguousArray<UInt8>().span,
      outputByteCount: 32,
      into: &shakeSpan
    )
    let shakeExpected = ContiguousArray<UInt8>([
      0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D,
      0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3E,
      0xD7, 0x3B, 0x80, 0x93, 0xF6, 0xEF, 0xBC, 0x88,
      0xEB, 0x1A, 0x6E, 0xAC, 0xFA, 0x66, 0xEF, 0x26,
    ])
    guard shake == shakeExpected else { throw Failure.sha3 }
  }

  private static func validateSHA256() throws {
    let input: ContiguousArray<UInt8> = [0x61, 0x62, 0x63]
    let expected: ContiguousArray<UInt8> = [
      0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    ]
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    do {
      var outputSpan = output.mutableSpan
      try SSL.SHA256.hash(input.span, into: &outputSpan)
    }
    guard output == expected else {
      throw Failure.sha256
    }
  }

  private static func validateHMACSHA256() throws {
    let key = ContiguousArray<UInt8>(repeating: 0x0B, count: 20)
    let message = ContiguousArray("Hi There".utf8)
    let expected: ContiguousArray<UInt8> = [
      0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
      0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
      0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
      0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7,
    ]
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: SSL.HMACSHA256.tagByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try SSL.HMACSHA256.authenticate(
        message.span,
        using: key.span,
        into: &outputSpan
      )
    }
    guard output == expected,
      try SSL.HMACSHA256.isValidAuthenticationCode(
        expected.span,
        authenticating: message.span,
        using: key.span
      )
    else {
      throw Failure.hmacSHA256
    }
  }

  private static func validateHKDFSHA256() throws {
    let inputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0x0B,
      count: 22
    )
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    let info = ContiguousArray(UInt8(0xF0)...UInt8(0xF9))
    let expectedPseudorandomKey: ContiguousArray<UInt8> = [
      0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
      0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
      0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
      0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5,
    ]
    let expectedOutputKeyMaterial: ContiguousArray<UInt8> = [
      0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
      0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
      0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
      0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF,
      0x34, 0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18,
      0x58, 0x65,
    ]

    var pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0,
      count: SSL.HKDFSHA256.pseudorandomKeyByteCount
    )
    do {
      var output = pseudorandomKey.mutableSpan
      try SSL.HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &output
      )
    }

    var outputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0,
      count: expectedOutputKeyMaterial.count
    )
    do {
      var output = outputKeyMaterial.mutableSpan
      try SSL.HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &output
      )
    }

    guard
      pseudorandomKey == expectedPseudorandomKey,
      outputKeyMaterial == expectedOutputKeyMaterial
    else {
      throw Failure.hkdfSHA256
    }
  }

  private static func validateUInt24Failure() throws {
    var builder = try ByteBuilder(maximumByteCount: 3)
    do {
      try builder.appendUInt24BigEndian(UInt32.max)
      throw Failure.uint24Failure
    } catch let error as ByteError {
      guard
        error
          == .integerDoesNotFit(
            value: UInt64(UInt32.max),
            byteCount: 3
          ), builder.count == 0
      else {
        throw Failure.uint24Failure
      }
    }
  }

  private static func validateByteCursor() throws {
    let input: ContiguousArray<UInt8> = [0x12, 0x34, 0x56]
    var cursor = ByteCursor(input.span)
    guard try cursor.readUInt16BigEndian() == 0x1234 else {
      throw Failure.byteCursor
    }
    guard try cursor.readByte() == 0x56 else {
      throw Failure.byteCursor
    }
    try cursor.requireFullyConsumed()
  }

  private static func validateQUICSecretEvent() throws {
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 1
      destination[1] = 2
      destination[2] = 3
      destination[3] = 4
    }
    let event = QUICTrafficSecretEvent(
      direction: .write,
      level: .handshake,
      cipherSuite: .aes128GCM_SHA256,
      secret: secret
    )
    let sum = event.withBorrowedSecret { bytes in
      bytes[0] + bytes[1] + bytes[2] + bytes[3]
    }
    guard sum == 10,
      event.direction == .write,
      event.level == .handshake,
      event.cipherSuite == .aes128GCM_SHA256
    else {
      throw Failure.quicSecret
    }
  }

  private static func validateQUICStepOutput() throws {
    let input: ContiguousArray<UInt8> = [1, 2, 3]
    let range = try ByteRange(offset: 0, count: 3)
    let actions: ContiguousArray<QUICTLSAction> = [
      .emitHandshakeBytes(level: .handshake, bytes: range),
      .handshakeComplete,
    ]
    let batch = try QUICTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: actions
    )
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 5
      destination[1] = 6
      destination[2] = 7
      destination[3] = 8
    }
    let event = QUICTrafficSecretEvent(
      direction: .write,
      level: .oneRTT,
      cipherSuite: .aes128GCM_SHA256,
      secret: secret
    )
    var slots = QUICTrafficSecretSlots()
    try slots.insert(event)
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .action(index: 0),
      .trafficSecret(direction: .write, level: .oneRTT),
      .action(index: 1),
    ]
    var output = try QUICTLSStepOutput(
      batch: batch,
      order: order,
      secrets: slots
    )

    guard let first = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume first {
    case .action(let action):
      guard
        action
          == .emitHandshakeBytes(
            level: .handshake,
            bytes: range
          )
      else {
        throw Failure.quicStepOutput
      }
    case .trafficSecret:
      throw Failure.quicStepOutput
    }

    guard let second = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume second {
    case .trafficSecret(let trafficSecret):
      let sum = trafficSecret.withBorrowedSecret { bytes in
        bytes[0] + bytes[1] + bytes[2] + bytes[3]
      }
      guard trafficSecret.direction == .write,
        trafficSecret.level == .oneRTT,
        sum == 26
      else {
        throw Failure.quicStepOutput
      }
    case .action:
      throw Failure.quicStepOutput
    }

    guard let third = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume third {
    case .action(let action):
      guard action == .handshakeComplete else {
        throw Failure.quicStepOutput
      }
    case .trafficSecret:
      throw Failure.quicStepOutput
    }

    let exhausted = try output.nextEffect()
    switch consume exhausted {
    case .none:
      guard output.remainingEffectCount == 0 else {
        throw Failure.quicStepOutput
      }
    case .some:
      throw Failure.quicStepOutput
    }
  }

  private static func validateDERCursor() throws {
    let input: ContiguousArray<UInt8> = [0x02, 0x01, 0x05]
    let limits = try ParsingLimits(
      maximumInputBytes: 64,
      maximumNestingDepth: 4,
      maximumElementCount: 8,
      maximumExtensionCount: 4,
      maximumOIDBytes: 32,
      maximumStringBytes: 32
    )
    var budget = try ParsingBudget(limits: limits, inputByteCount: input.count)
    var cursor = DERCursor(input.span)
    let integer = try cursor.readElement(using: &budget)
    guard integer.tag.tagClass == .universal,
      integer.tag.number == 2,
      integer.contentBytes.count == 1,
      integer.contentBytes[0] == 5
    else {
      throw Failure.derCursor
    }
  }

  private static func validateSecretOwner() throws {
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 1
      destination[1] = 2
      destination[2] = 3
      destination[3] = 4
    }
    let sum = secret.withBorrowedBytes { bytes in
      var result: UInt8 = 0
      var index = 0
      while index < bytes.count {
        result &+= bytes[index]
        index += 1
      }
      return result
    }
    guard sum == 10 else {
      throw Failure.secretOwner
    }
  }

  private static func validateActionBatch() throws {
    let input: ContiguousArray<UInt8> = [1, 2, 3]
    let range = try ByteRange(offset: 0, count: 3)
    var streamActions = ContiguousArray<TLSStreamAction>()
    streamActions.reserveCapacity(1)
    streamActions.append(.emitRecordBytes(range))
    let streamBatch = try TLSStreamActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: streamActions
    )

    var datagramActions = ContiguousArray<DTLSAction>()
    datagramActions.reserveCapacity(1)
    datagramActions.append(.emitDatagram(range))
    let datagramBatch = try DTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: datagramActions
    )

    var quicActions = ContiguousArray<QUICTLSAction>()
    quicActions.reserveCapacity(1)
    quicActions.append(.emitHandshakeBytes(level: .handshake, bytes: range))
    let quicBatch = try QUICTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: quicActions
    )

    guard streamBatch.actions.count == 1,
      datagramBatch.actions.count == 1,
      quicBatch.actions.count == 1,
      streamBatch.bytes.count == 3,
      datagramBatch.bytes.count == 3,
      quicBatch.bytes.count == 3
    else {
      throw Failure.actionBatch
    }
  }

  private static func validateProfiles() throws {
    guard TLSStream13Profile.usesTLSRecords,
      !DTLS13Profile.usesTLSRecords,
      DTLS13Profile.usesDatagramReliability,
      !QUICTLSProfile.usesTLSRecords
    else {
      throw Failure.profileBoundary
    }
  }

  private static func hexadecimalBytes(
    _ hexadecimal: String
  ) throws(Failure) -> ContiguousArray<UInt8> {
    let characters = ContiguousArray(hexadecimal.utf8)
    guard characters.count & 1 == 0 else {
      throw .rsaPSS
    }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(characters.count / 2)
    var index = 0
    while index < characters.count {
      guard let high = hexadecimalNibble(characters[index]),
        let low = hexadecimalNibble(characters[index + 1])
      else {
        throw .rsaPSS
      }
      result.append(high << 4 | low)
      index += 2
    }
    return result
  }

  private static func hexadecimalNibble(_ character: UInt8) -> UInt8? {
    switch character {
    case 0x30...0x39: character - 0x30
    case 0x41...0x46: character - 0x41 + 10
    case 0x61...0x66: character - 0x61 + 10
    default: nil
    }
  }
}
