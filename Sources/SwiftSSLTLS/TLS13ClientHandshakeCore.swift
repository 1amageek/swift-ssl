import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

/// Record-independent TLS 1.3 client state machine.
///
/// The core consumes exactly one complete handshake message per receive call.
/// It owns transcript and key-schedule state, but never frames, seals, opens,
/// retransmits, or reassembles transport bytes.
public struct TLS13ClientHandshakeCore:
  TLS13ClientHandshakeCoreProtocol,
  TLS13ApplicationTrafficSecretManaging,
  ~Copyable,
  Sendable
{
  private enum Phase: Sendable {
    case idle
    case awaitingServerHello
    case awaitingServerFlight
    case established
    case failed
  }

  private let random: OwnedBytes
  private let serverName: OwnedBytes?
  private var keyExchange: TLS13ClientKeyExchangeState
  private let expectedServerPublicKey: Ed25519PublicKey
  private let echMaximumNameLength: UInt8?
  private let echOuterRandom: OwnedBytes?
  private let echPublicName: OwnedBytes?
  private let echExpectedPublicServerKey: Ed25519PublicKey?
  private let verificationInstant: VerificationInstant
  private let cipherSuite: TLSCipherSuite
  private var transcript: TLS13Transcript
  private var echConfiguration: ECHClientConfiguration?
  private var echInnerClientHello: OwnedBytes?
  private var echOuterClientHello: OwnedBytes?
  private var echWasRejected: Bool
  private var echRetryConfigurations: ECHConfigList?
  private var resumptionState: TLS13ResumptionState?
  private var resumptionPSK: SecretBytes?
  private var offeredResumption: Bool
  private var resumedHandshake: Bool
  private var handshakeSecrets: TLS13HandshakeSecrets?
  private var applicationSecrets: TLS13ApplicationSecrets?
  private var resumptionMasterSecret: TLS13ResumptionMasterSecret?
  private var sawEncryptedExtensions: Bool
  private var sawCertificate: Bool
  private var sawCertificateVerify: Bool
  private var phase: Phase

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    expectedServerPublicKey: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(
        x25519: TLS13X25519ClientKeyExchange(privateKey: ephemeralKey)
      ),
      expectedServerPublicKey: expectedServerPublicKey,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      echConfiguration: consume echConfiguration
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ClientKeyExchange,
    expectedServerPublicKey: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519: keyExchange),
      expectedServerPublicKey: expectedServerPublicKey,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      echConfiguration: consume echConfiguration
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    expectedServerPublicKey: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519MLKEM768: keyExchange),
      expectedServerPublicKey: expectedServerPublicKey,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      echConfiguration: consume echConfiguration
    )
  }

  private init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13ClientKeyExchangeState,
    expectedServerPublicKey: Span<UInt8>,
    serverName: Span<UInt8>?,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite,
    resumptionState: consuming TLS13ResumptionState?,
    echConfiguration: consuming ECHClientConfiguration?
  ) throws(TLS13HandshakeEngineError) {
    guard random.count == 32 else {
      throw .invalidConfiguration
    }
    guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
      throw .unsupportedCipherSuite(cipherSuite.rawValue)
    }
    let validatedServerPublicKey: Ed25519PublicKey
    do {
      validatedServerPublicKey = try Ed25519PublicKey(bytes: expectedServerPublicKey)
    } catch {
      throw .invalidConfiguration
    }
    do {
      transcript = try TLS13Transcript()
    } catch let error {
      throw .handshake(error)
    }
    self.random = OwnedBytes(copying: random)
    if let serverName {
      self.serverName = OwnedBytes(copying: serverName)
    } else {
      self.serverName = nil
    }
    self.keyExchange = consume keyExchange
    self.expectedServerPublicKey = validatedServerPublicKey
    echMaximumNameLength = echConfiguration?.selectedConfiguration.config.maximumNameLength
    echOuterRandom = echConfiguration?.outerRandom
    echPublicName = echConfiguration?.publicName
    echExpectedPublicServerKey = echConfiguration?.expectedPublicServerKey
    self.verificationInstant = verificationInstant
    self.cipherSuite = cipherSuite
    self.resumptionState = resumptionState
    self.echConfiguration = consume echConfiguration
    echInnerClientHello = nil
    echOuterClientHello = nil
    echWasRejected = false
    echRetryConfigurations = nil
    resumptionPSK = nil
    offeredResumption = false
    resumedHandshake = false
    handshakeSecrets = nil
    applicationSecrets = nil
    resumptionMasterSecret = nil
    sawEncryptedExtensions = false
    sawCertificate = false
    sawCertificateVerify = false
    phase = .idle
  }

  public var isEstablished: Bool {
    if case .established = phase { return true }
    return false
  }

  public mutating func start()
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput
  {
    guard case .idle = phase else { throw .invalidState }
    do {
      let namedGroup = keyExchange.namedGroup
      let clientHello = try keyExchange.withClientShare { keyShare in
        let clientHello: OwnedBytes
        if var state = resumptionState.take() {
          guard state.cipherSuite == cipherSuite else {
            throw TLS13HandshakeEngineError.invalidConfiguration
          }
          let psk = try state.consumePSK()
          let ticketAge = try state.obfuscatedTicketAge(at: verificationInstant)
          let identity = try state.withTicketBytes { ticket throws(TLS13PSKError) in
            try TLS13PSKIdentity(identity: ticket, obfuscatedTicketAge: ticketAge)
          }
          let binderLength = TLS13KeySchedule.hashByteCount(for: cipherSuite)
          let zeroBinder = try TLS13PSKBinder(
            value: ContiguousArray<UInt8>(repeating: 0, count: binderLength).span
          )
          let zeroExtension = try TLS13PreSharedKeyExtension(
            identities: ContiguousArray([identity]),
            binders: ContiguousArray([zeroBinder])
          )
          let zeroHello = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: namedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: serverName,
            preSharedKey: zeroExtension
          )
          let actualBinder = try makeResumptionBinder(
            preSharedKey: psk,
            cipherSuite: cipherSuite,
            zeroClientHello: zeroHello.span,
            echMaximumNameLength: echMaximumNameLength
          )
          let actualExtension = try TLS13PreSharedKeyExtension(
            identities: ContiguousArray([identity]),
            binders: ContiguousArray([actualBinder])
          )
          clientHello = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: namedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: serverName,
            preSharedKey: actualExtension
          )
          resumptionPSK = consume psk
          offeredResumption = true
        } else {
          clientHello = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: namedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: serverName
          )
        }
        return clientHello
      }
      if var configuration = echConfiguration.take() {
        guard let outerRandom = echOuterRandom,
          let publicName = echPublicName
        else {
          throw TLS13HandshakeEngineError.invalidConfiguration
        }
        let outerTemplate = try keyExchange.withClientShare { keyShare in
          try TLS13HandshakeCodec.makeClientHello(
            random: outerRandom.span,
            namedGroup: namedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: publicName
          )
        }
        let offer = try configuration.seal(
          innerClientHello: clientHello.span,
          outerClientHello: outerTemplate.span
        )
        echConfiguration = consume configuration
        echInnerClientHello = offer.innerClientHello
        echOuterClientHello = offer.outerClientHello
        return try completeStart(
          transcriptClientHello: offer.innerClientHello,
          wireClientHello: offer.outerClientHello
        )
      }
      return try completeStart(
        transcriptClientHello: clientHello,
        wireClientHello: clientHello
      )
    } catch let error {
      phase = .failed
      throw mapHandshakeEngineError(error)
    }
  }

  private mutating func completeStart(
    transcriptClientHello: OwnedBytes,
    wireClientHello: consuming OwnedBytes
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    try appendTranscript(transcriptClientHello.span)
    phase = .awaitingServerHello
    return try makeEmission(wireClientHello, at: .initial)
  }

  public mutating func receiveHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    do {
      switch phase {
      case .awaitingServerHello:
        guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveServerHello(message)
      case .awaitingServerFlight:
        guard epoch == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveServerFlightMessage(message)
      case .idle, .established, .failed:
        throw TLS13HandshakeEngineError.invalidState
      }
    } catch let error as TLS13HandshakeEngineError {
      phase = .failed
      throw error
    } catch {
      phase = .failed
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func updateApplicationTrafficSecret(
    for endpoint: TLSRole
  ) throws(TLS13HandshakeEngineError) -> TLS13TrafficSecret {
    guard case .established = phase,
      var secrets = applicationSecrets.take()
    else {
      throw .invalidState
    }
    do {
      switch endpoint {
      case .client: try secrets.updateClientTrafficSecret()
      case .server: try secrets.updateServerTrafficSecret()
      }
      let exported = try secrets.exportTrafficSecret(for: endpoint)
      applicationSecrets = consume secrets
      return exported
    } catch let error as TLS13KeyScheduleError {
      applicationSecrets = consume secrets
      phase = .failed
      throw .keySchedule(error)
    } catch {
      applicationSecrets = consume secrets
      phase = .failed
      throw .malformedInput
    }
  }

  public mutating func makeResumptionState(
    ticket: TLS13NewSessionTicket,
    receivedAt: VerificationInstant
  ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState {
    guard case .established = phase,
      let secrets = applicationSecrets.take()
    else {
      throw .invalidState
    }
    guard let masterSecret = resumptionMasterSecret.take() else {
      applicationSecrets = consume secrets
      throw .invalidState
    }
    do {
      let state = try masterSecret.withBorrowedBytes {
        master throws(TLS13ResumptionError) in
        try TLS13ResumptionState(
          ticket: ticket.ticket.span,
          ticketNonce: ticket.ticketNonce.span,
          resumptionMasterSecret: master,
          cipherSuite: secrets.cipherSuite,
          issuedAt: receivedAt,
          lifetime: ticket.lifetime,
          ageAdd: ticket.ageAdd
        )
      }
      applicationSecrets = consume secrets
      resumptionMasterSecret = consume masterSecret
      return state
    } catch let error {
      applicationSecrets = consume secrets
      resumptionMasterSecret = consume masterSecret
      phase = .failed
      throw .resumption(error)
    }
  }

  private mutating func receiveServerHello(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let serverHello = try engineTry {
      try TLS13HandshakeCodec.parseServerHello(message)
    }
    guard serverHello.cipherSuite == cipherSuite else {
      throw .unsupportedCipherSuite(serverHello.cipherSuite.rawValue)
    }
    guard serverHello.namedGroup == keyExchange.namedGroup else {
      throw .keyExchange(
        .unexpectedNamedGroup(
          expected: keyExchange.namedGroup,
          actual: serverHello.namedGroup
        ))
    }
    guard !serverHello.selectedPreSharedKey || offeredResumption else {
      throw .handshake(.unexpectedMessage(type: TLS13HandshakeCodec.serverHelloType))
    }
    if let innerClientHello = echInnerClientHello {
      let accepted: Bool
      do {
        accepted = try ECHAcceptanceConfirmation.isAccepted(
          innerClientHello: innerClientHello.span,
          serverHello: message,
          cipherSuite: cipherSuite
        )
      } catch let error {
        throw .ech(error)
      }
      if accepted {
        echWasRejected = false
        echOuterClientHello = nil
        try appendTranscript(message)
      } else {
        guard !serverHello.selectedPreSharedKey,
          let outerClientHello = echOuterClientHello
        else {
          throw .ech(.invalidClientHello)
        }
        do {
          transcript = try TLS13Transcript()
          try transcript.append(outerClientHello.span)
          try transcript.append(message)
        } catch let error {
          throw .handshake(error)
        }
        echWasRejected = true
      }
    } else {
      try appendTranscript(message)
    }
    resumedHandshake = offeredResumption && serverHello.selectedPreSharedKey

    let sharedSecret: SecretBytes
    do {
      sharedSecret = try keyExchange.complete(serverShare: serverHello.keyShare.span)
    } catch let error {
      throw .keyExchange(error)
    }
    let transcriptHash = try transcriptDigest()
    let schedule: TLS13KeySchedule
    if resumedHandshake {
      guard let psk = resumptionPSK.take() else { throw .invalidState }
      do {
        schedule = try psk.withBorrowedBytes { bytes in
          try TLS13KeySchedule(cipherSuite: cipherSuite, preSharedKey: bytes)
        }
      } catch {
        throw mapHandshakeEngineError(error)
      }
    } else {
      resumptionPSK = nil
      schedule = try engineTry {
        try TLS13KeySchedule(
          cipherSuite: cipherSuite,
          preSharedKey: ContiguousArray<UInt8>().span
        )
      }
    }
    // Swift 6.4's move-only checker cannot lower a noncopyable
    // TLS13HandshakeSecrets return directly from the SecretBytes borrow closure.
    // Materialize only the 32/64-byte combined secret, then wipe it after HKDF.
    var sharedBytes = ContiguousArray<UInt8>()
    defer { wipe(&sharedBytes) }
    sharedSecret.withBorrowedBytes { shared in
      sharedBytes.reserveCapacity(shared.count)
      var index = 0
      while index < shared.count {
        sharedBytes.append(shared[index])
        index += 1
      }
    }
    let secrets: TLS13HandshakeSecrets
    do {
      secrets = try schedule.makeHandshakeSecrets(
        ecdheSharedSecret: sharedBytes.span,
        transcriptHash: transcriptHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let exported: TLS13TrafficSecretPair
    do {
      exported = try secrets.exportTrafficSecrets()
    } catch {
      throw .malformedInput
    }
    handshakeSecrets = consume secrets
    phase = .awaitingServerFlight
    return try makeEmptyOutput(
      actions: [.installTrafficSecrets(epoch: .handshake)],
      handshakeSecrets: exported
    )
  }

  private mutating func receiveServerFlightMessage(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard !message.isEmpty else { throw .malformedInput }
    switch message[0] {
    case TLS13HandshakeCodec.encryptedExtensionsType:
      guard !sawEncryptedExtensions, !sawCertificate else { throw .malformedInput }
      let retryConfigurations = try engineTry {
        try TLS13HandshakeCodec.parseEncryptedExtensions(message)
      }
      if echInnerClientHello != nil {
        if echWasRejected {
          echRetryConfigurations = retryConfigurations
        } else if retryConfigurations != nil {
          throw .ech(.invalidClientHello)
        }
      } else if retryConfigurations != nil {
        throw .ech(.invalidClientHello)
      }
      try appendTranscript(message)
      sawEncryptedExtensions = true
      return try makeEmptyOutput()

    case TLS13HandshakeCodec.certificateType:
      guard !resumedHandshake, sawEncryptedExtensions, !sawCertificate else {
        throw .malformedInput
      }
      let certificateBytes = try engineTry {
        try TLS13HandshakeCodec.parseCertificate(message)
      }
      let certificate: X509Certificate
      do {
        certificate = try X509Certificate(der: certificateBytes.span)
        try certificate.verifySignature()
      } catch let error {
        throw .certificate(error)
      }
      guard certificate.validity.contains(verificationInstant) else {
        throw .certificateNotValid
      }
      guard certificate.subjectPublicKeyInfo.isEd25519 else {
        throw .certificateVerificationFailed
      }
      let authenticatedName: OwnedBytes?
      if echWasRejected {
        guard let publicKey = echExpectedPublicServerKey,
          let publicName = echPublicName
        else {
          throw .invalidConfiguration
        }
        guard certificatePublicKeyMatches(certificate, expected: publicKey) else {
          throw .certificateKeyMismatch
        }
        authenticatedName = publicName
      } else {
        guard
          certificatePublicKeyMatches(
            certificate,
            expected: expectedServerPublicKey
          )
        else {
          throw .certificateKeyMismatch
        }
        authenticatedName = serverName
      }
      if let authenticatedName {
        do {
          try certificate.verifyDNSName(authenticatedName.span)
        } catch {
          throw .certificateVerificationFailed
        }
      }
      try appendTranscript(message)
      sawCertificate = true
      return try makeEmptyOutput()

    case TLS13HandshakeCodec.certificateVerifyType:
      guard !resumedHandshake, sawCertificate, !sawCertificateVerify else {
        throw .malformedInput
      }
      let certificateVerify = try engineTry {
        try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message)
      }
      guard certificateVerify.signatureScheme == .ed25519 else {
        throw .certificateVerifyFailure
      }
      let hash = try transcriptDigest()
      let signed = TLS13HandshakeWire.certificateVerifyInput(transcriptHash: hash.span)
      let verificationKey = try activeServerPublicKey()
      guard
        try verifyCertificateVerify(
          certificateVerify,
          signedMessage: signed.span,
          publicKey: verificationKey
        )
      else {
        throw .certificateVerifyFailure
      }
      try appendTranscript(message)
      sawCertificateVerify = true
      return try makeEmptyOutput()

    case TLS13HandshakeCodec.finishedType:
      guard sawEncryptedExtensions,
        resumedHandshake || sawCertificateVerify
      else {
        throw .malformedInput
      }
      return try receiveServerFinished(message)

    default:
      throw .handshake(.unexpectedMessage(type: message[0]))
    }
  }

  private mutating func receiveServerFinished(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let finished = try engineTry {
      try TLS13HandshakeCodec.parseFinished(
        message,
        hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
      )
    }
    let verificationHash = try transcriptDigest()
    guard let secrets = handshakeSecrets.take() else { throw .invalidState }
    let expected: OwnedBytes
    do {
      expected = try secrets.makeServerFinishedVerifyData(
        transcriptHash: verificationHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    guard ConstantTime.equal(finished.span, expected.span) else {
      throw .certificateVerifyFailure
    }
    try appendTranscript(message)
    if echWasRejected {
      phase = .failed
      throw .echRequired(retryConfigurations: echRetryConfigurations)
    }
    let applicationHash = try transcriptDigest()
    let clientFinishedData: OwnedBytes
    do {
      clientFinishedData = try secrets.makeClientFinishedVerifyData(
        transcriptHash: applicationHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let clientFinished: OwnedBytes
    do {
      clientFinished = try TLS13HandshakeCodec.makeFinished(
        verifyData: clientFinishedData.span
      )
    } catch {
      throw mapHandshakeEngineError(error)
    }
    let derived: TLS13ApplicationSecrets
    do {
      derived = try secrets.makeApplicationSecrets(
        transcriptHash: applicationHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    try appendTranscript(clientFinished.span)
    let completedHash = try transcriptDigest()
    let resumption: TLS13ResumptionMasterSecret
    do {
      resumption = try secrets.makeResumptionMasterSecret(
        transcriptHash: completedHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let exported: TLS13TrafficSecretPair
    do {
      exported = try derived.exportTrafficSecrets()
    } catch {
      throw .malformedInput
    }
    applicationSecrets = consume derived
    resumptionMasterSecret = consume resumption
    phase = .established
    let range: ByteRange
    do {
      range = try ByteRange(offset: 0, count: clientFinished.count)
    } catch let error {
      throw .output(error)
    }
    return try makeOutput(
      bytes: clientFinished,
      actions: [
        .emitHandshakeBytes(epoch: .handshake, bytes: range),
        .installTrafficSecrets(epoch: .application),
        .handshakeComplete,
      ],
      applicationSecrets: exported
    )
  }

  private func verifyCertificateVerify(
    _ value: TLS13CertificateVerify,
    signedMessage: Span<UInt8>,
    publicKey: Ed25519PublicKey
  ) throws(TLS13HandshakeEngineError) -> Bool {
    do {
      return try Ed25519.verify(
        signature: value.signature.span,
        message: signedMessage,
        using: publicKey
      )
    } catch {
      throw .certificateVerifyFailure
    }
  }

  private func activeServerPublicKey()
    throws(TLS13HandshakeEngineError) -> Ed25519PublicKey
  {
    if echWasRejected {
      guard let publicKey = echExpectedPublicServerKey else {
        throw .invalidConfiguration
      }
      return publicKey
    }
    return expectedServerPublicKey
  }

  private func certificatePublicKeyMatches(
    _ certificate: X509Certificate,
    expected: borrowing Ed25519PublicKey
  ) -> Bool {
    certificate.subjectPublicKeyInfo.withPublicKeyBytes { key in
      ConstantTime.equal(key, expected.span)
    }
  }

  private mutating func appendTranscript(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) {
    do {
      try transcript.append(message)
    } catch let error {
      throw .handshake(error)
    }
  }

  private borrowing func transcriptDigest()
    throws(TLS13HandshakeEngineError) -> OwnedBytes
  {
    do {
      return try transcript.digest(for: cipherSuite)
    } catch let error {
      throw .handshake(error)
    }
  }

  private func makeEmission(
    _ message: OwnedBytes,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let range: ByteRange
    do {
      range = try ByteRange(offset: 0, count: message.count)
    } catch let error {
      throw .output(error)
    }
    return try makeOutput(
      bytes: message,
      actions: [.emitHandshakeBytes(epoch: epoch, bytes: range)]
    )
  }

  private func makeEmptyOutput(
    actions: ContiguousArray<TLS13HandshakeCoreAction> = [],
    handshakeSecrets: consuming TLS13TrafficSecretPair? = nil
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    try makeOutput(
      bytes: OwnedBytes(),
      actions: actions,
      handshakeSecrets: handshakeSecrets
    )
  }

  private func makeOutput(
    bytes: consuming OwnedBytes,
    actions: consuming ContiguousArray<TLS13HandshakeCoreAction>,
    handshakeSecrets: consuming TLS13TrafficSecretPair? = nil,
    applicationSecrets: consuming TLS13TrafficSecretPair? = nil
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    do {
      return try TLS13HandshakeCoreOutput(
        bytes: bytes,
        actions: actions,
        handshakeSecrets: handshakeSecrets,
        applicationSecrets: applicationSecrets
      )
    } catch let error {
      switch error {
      case .byteRange(let byteError): throw .output(byteError)
      case .duplicateTrafficSecrets, .missingTrafficSecrets,
        .unreferencedTrafficSecrets:
        throw .invalidState
      }
    }
  }
}

private func makeResumptionBinder(
  preSharedKey: borrowing SecretBytes,
  cipherSuite: TLSCipherSuite,
  zeroClientHello: Span<UInt8>,
  echMaximumNameLength: UInt8?
) throws -> TLS13PSKBinder {
  if let maximumNameLength = echMaximumNameLength {
    let inner = try ECHClientHelloCodec.makeInner(
      from: zeroClientHello,
      maximumNameLength: maximumNameLength
    ).clientHello
    let truncated = try TLS13HandshakeCodec.truncatedClientHelloForBinder(
      inner.span
    )
    var transcript = try TLS13Transcript()
    try transcript.append(truncated.span)
    let transcriptHash = try transcript.digest(for: cipherSuite)
    return try makeBinder(
      preSharedKey: preSharedKey,
      cipherSuite: cipherSuite,
      transcriptHash: transcriptHash.span
    )
  }
  let truncated = try TLS13HandshakeCodec.truncatedClientHelloForBinder(
    zeroClientHello
  )
  var transcript = try TLS13Transcript()
  try transcript.append(truncated.span)
  let transcriptHash = try transcript.digest(for: cipherSuite)
  return try makeBinder(
    preSharedKey: preSharedKey,
    cipherSuite: cipherSuite,
    transcriptHash: transcriptHash.span
  )
}

private func makeBinder(
  preSharedKey: borrowing SecretBytes,
  cipherSuite: TLSCipherSuite,
  transcriptHash: Span<UInt8>
) throws -> TLS13PSKBinder {
  let binder = try TLS13PSKBinder.compute(
    preSharedKey: preSharedKey,
    cipherSuite: cipherSuite,
    transcriptHash: transcriptHash
  )
  return try TLS13PSKBinder(value: binder.span)
}
