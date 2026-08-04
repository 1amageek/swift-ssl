import SSLCore
import SSLCrypto
import SSLTLS
import SSLTypes

/// QUIC TLS server mechanism driven by complete TLS handshake messages.
///
/// QUIC owns packet parsing, CRYPTO offsets, and reassembly. This type owns
/// only TLS 1.3 handshake state and maps its effects to QUIC encryption levels.
public struct QUICTLSServerHandshake: QUICTLSServerHandshaking, ~Copyable, Sendable {
  private var core: TLS13ServerHandshakeCore

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        certificateEntries: certificateEntries,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        certificateDER: certificateDER,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        certificateEntries: certificateEntries,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        certificateDER: certificateDER,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        certificateEntries: certificateEntries,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        certificateDER: certificateDER,
        signingKey: signingKey,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        externalServerCredential: externalServerCredential,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        externalServerCredential: externalServerCredential,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector: any TLS13ApplicationProtocolSelecting,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>,
    resumptionIdentity: Span<UInt8>? = nil,
    resumptionPSK: Span<UInt8>? = nil,
    resumptionIssuedAt: VerificationInstant? = nil,
    resumptionLifetime: UInt32? = nil,
    resumptionAgeAdd: UInt32? = nil,
    resumptionAgeToleranceMilliseconds: UInt32 = 10_000,
    resumptionMaximumEarlyDataByteCount: UInt32 = 0,
    resumptionApplicationProtocol: TLS13ApplicationProtocol? = nil,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration? = nil,
    echConfigurations: ECHServerConfigurationSet? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        keyExchangeEntropy: keyExchangeEntropy,
        externalServerCredential: externalServerCredential,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        transportParameters: transportParameters,
        resumptionIdentity: resumptionIdentity,
        resumptionPSK: resumptionPSK,
        resumptionIssuedAt: resumptionIssuedAt,
        resumptionLifetime: resumptionLifetime,
        resumptionAgeAdd: resumptionAgeAdd,
        resumptionAgeToleranceMilliseconds: resumptionAgeToleranceMilliseconds,
        resumptionMaximumEarlyDataByteCount: resumptionMaximumEarlyDataByteCount,
        resumptionApplicationProtocol: resumptionApplicationProtocol,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfigurations: echConfigurations,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  private init(
    core: consuming TLS13ServerHandshakeCore
  ) {
    self.core = core
  }

  public var isEstablished: Bool { core.isEstablished }

  public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
    core.negotiatedApplicationProtocol
  }

  public var receivedTransportParameters: OwnedBytes? {
    core.receivedTransportParameters
  }

  /// Configures the local QUIC transport parameters before the first server
  /// flight is produced.
  public mutating func configureTransportParameters(
    _ parameters: Span<UInt8>
  ) throws(QUICTLSHandshakeError) {
    do {
      try core.configureTransportParameters(parameters)
    } catch let error {
      throw .handshake(error)
    }
  }

  public var authenticatedClientIdentity: TLS13ValidatedClientCertificate? {
    core.authenticatedClientIdentity
  }

  public var earlyDataState: TLS13EarlyDataState { core.earlyDataState }

  public var earlyDataByteLimit: UInt32 { core.earlyDataByteLimit }

  public mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(QUICTLSHandshakeError) {
    do {
      try core.configureCertificateCompression(configuration)
    } catch let error {
      throw .handshake(error)
    }
  }

  /// Processes one complete TLS handshake message supplied by the transport
  /// owner. QUIC CRYPTO offsets and reassembly stay outside this mechanism
  /// package; callers must pass a complete, header-inclusive message.
  public mutating func processHandshakeMessage(
    _ message: Span<UInt8>,
    at level: QUICTLSHandshakeInputLevel
  ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput {
    let epoch: TLS13HandshakeEpoch = level == .initial ? .initial : .handshake
    let output: TLS13HandshakeCoreOutput
    do {
      output = try core.receiveHandshakeMessage(message, at: epoch)
    } catch let error {
      throw .handshake(error)
    }
    return try QUICTLSCoreOutputAdapter.adapt(output, role: .server)
  }

  /// Stepwise variant that preserves swift-ssl capability suspension.
  public mutating func processHandshakeMessageStep(
    _ message: Span<UInt8>,
    at level: QUICTLSHandshakeInputLevel
  ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition {
    let epoch: TLS13HandshakeEpoch = level == .initial ? .initial : .handshake
    let transition: TLS13HandshakeCoreTransition
    do {
      transition = try core.receiveHandshakeMessageStep(message, at: epoch)
    } catch let error {
      throw .handshake(error)
    }
    switch consume transition {
    case .output(let output):
      return .output(try QUICTLSCoreOutputAdapter.adapt(output, role: .server))
    case .suspended(let request):
      return .suspended(request)
    }
  }

  public mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition {
    let transition: TLS13HandshakeCoreTransition
    do {
      transition = try core.resume(response)
    } catch let error {
      throw .handshake(error)
    }
    switch consume transition {
    case .output(let output):
      return .output(try QUICTLSCoreOutputAdapter.adapt(output, role: .server))
    case .suspended(let request):
      return .suspended(request)
    }
  }

  public mutating func updateOneRTTTrafficSecret(
    for direction: QUICSecretDirection
  ) throws(QUICTLSHandshakeError) -> QUICTrafficSecretEvent {
    let endpoint: TLSRole = direction == .read ? .client : .server
    let trafficSecret: TLS13TrafficSecret
    do {
      trafficSecret = try core.updateQUICApplicationTrafficSecret(for: endpoint)
    } catch let error {
      throw .handshake(error)
    }
    let cipherSuite = trafficSecret.cipherSuite
    return QUICTrafficSecretEvent(
      direction: direction,
      level: .oneRTT,
      cipherSuite: cipherSuite,
      secret: trafficSecret.takeSecret()
    )
  }

}
