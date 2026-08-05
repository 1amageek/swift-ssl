import SSLCore
import SSLCrypto
import SSLTLS
import TLSTypes

/// QUIC TLS client mechanism driven by complete TLS handshake messages.
///
/// QUIC owns packet parsing, CRYPTO offsets, and reassembly. This type owns
/// only TLS 1.3 handshake state and maps its effects to QUIC encryption levels.
public struct QUICTLSClientHandshake: QUICTLSClientHandshaking, ~Copyable, Sendable {
  private var core: TLS13ClientHandshakeCore

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
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
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
  ) throws(QUICTLSHandshakeError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        transportParameters: transportParameters,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        resumptionState: resumptionState,
        earlyDataConfiguration: earlyDataConfiguration,
        echConfiguration: consume echConfiguration,
        handshakeEncoding: .quic
      )
    } catch let error {
      throw .handshake(error)
    }
    return Self(core: consume core)
  }

  private init(
    core: consuming TLS13ClientHandshakeCore
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

  /// Configures the local QUIC transport parameters before `start()`.
  public mutating func configureTransportParameters(
    _ parameters: Span<UInt8>
  ) throws(QUICTLSHandshakeError) {
    do {
      try core.configureTransportParameters(parameters)
    } catch let error {
      throw .handshake(error)
    }
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

  public mutating func start()
    throws(QUICTLSHandshakeError) -> QUICTLSStepOutput
  {
    let output: TLS13HandshakeCoreOutput
    do {
      output = try core.start()
    } catch let error {
      throw .handshake(error)
    }
    return try QUICTLSCoreOutputAdapter.adapt(output, role: .client)
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
    return try QUICTLSCoreOutputAdapter.adapt(output, role: .client)
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
      return .output(try QUICTLSCoreOutputAdapter.adapt(output, role: .client))
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
      return .output(try QUICTLSCoreOutputAdapter.adapt(output, role: .client))
    case .suspended(let request):
      return .suspended(request)
    }
  }

  public mutating func updateOneRTTTrafficSecret(
    for direction: QUICSecretDirection
  ) throws(QUICTLSHandshakeError) -> QUICTrafficSecretEvent {
    let endpoint: TLSRole = direction == .read ? .server : .client
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
