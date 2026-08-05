import SSLCore
import SSLCrypto
import SSLX509

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
    case awaitingServerHelloAfterRetry
    case awaitingServerFlight
    case suspendedForPeerTrust
    case suspendedForCredentialSelection
    case suspendedForSignature
    case suspendedForPostHandshakeCredentialSelection
    case suspendedForPostHandshakeSignature
    case established
    case failed
  }

  private let random: OwnedBytes
  private let serverName: OwnedBytes?
  private var keyExchange: TLS13ClientKeyExchangeState
  private let certificateValidator: (any TLS13ServerCertificateValidating)?
  private let configuredServerCertificateType: TLS13CertificateType
  private let configuredClientCertificateType: TLS13CertificateType
  private let offersPostHandshakeAuthentication: Bool
  private var clientIdentity: TLS13ClientIdentity?
  private let usesExternalClientCredential: Bool
  private var selectedExternalClientCredential: TLS13CredentialDescriptor?
  private let applicationProtocols: ContiguousArray<TLS13ApplicationProtocol>
  private var localTransportParameters: OwnedBytes?
  private var validatedServerPublicKey: TLS13CertificateVerificationKey?
  private let echMaximumNameLength: UInt8?
  private let echOuterRandom: OwnedBytes?
  private let echPublicName: OwnedBytes?
  private let verificationInstant: VerificationInstant
  private let cipherSuite: TLSCipherSuite
  private let handshakeEncoding: TLS13HandshakeEncoding
  private var localConnectionID: OwnedBytes?
  private var expectedPeerConnectionID: OwnedBytes?
  private var srtpConfiguration: DTLSSRTPClientConfiguration?
  private var negotiatedSRTPProtectionProfile: DTLSSRTPProtectionProfile?
  private var negotiatedSRTPMasterKeyIdentifier: OwnedBytes?
  private var transcript: TLS13Transcript
  private var echConfiguration: ECHClientConfiguration?
  private var echInnerClientHello: OwnedBytes?
  private var echOuterClientHello: OwnedBytes?
  private var retryClientHello: OwnedBytes?
  private var echAcceptanceConfirmedByRetry: Bool
  private var echWasRejected: Bool
  private var echRetryConfigurations: ECHConfigList?
  private var resumptionState: TLS13ResumptionState?
  private let earlyDataConfiguration: TLS13EarlyDataClientConfiguration?
  private var resumptionPSK: SecretBytes?
  private var offeredResumption: Bool
  private var resumedHandshake: Bool
  private var earlyDataStateStorage: TLS13EarlyDataState
  private var earlyDataByteLimitStorage: UInt32
  private var handshakeSecrets: TLS13HandshakeSecrets?
  private var applicationSecrets: TLS13ApplicationSecrets?
  private var resumptionMasterSecret: TLS13ResumptionMasterSecret?
  private var sawEncryptedExtensions: Bool
  private var certificateRequest: TLS13CertificateRequest?
  private var sawCertificate: Bool
  private var sawCertificateVerify: Bool
  private var negotiatedServerCertificateType: TLS13CertificateType
  private var negotiatedClientCertificateType: TLS13CertificateType
  private var certificateCompression:
    TLS13CertificateCompressionConfiguration?
  private var selectedApplicationProtocol: TLS13ApplicationProtocol?
  private var peerTransportParameters: OwnedBytes?
  private var capabilitySequencer: TLS13CapabilitySequencer
  private var pendingServerTrust: PendingServerTrust?
  private var pendingClientCredentialSelection: PendingClientCredentialSelection?
  private var pendingClientSignature: PendingClientSignature?
  private var pendingClientEndOfEarlyData: OwnedBytes?
  private var postHandshakeTranscript: TLS13Transcript?
  private var postHandshakeRequest: TLS13CertificateRequest?
  private var postHandshakeCredential: TLS13CredentialDescriptor?
  private var postHandshakeFlightPrefix: ContiguousArray<OwnedBytes>
  private var postHandshakeSignedMessage: OwnedBytes?
  private var pendingPostHandshakeCapabilityToken: TLS13CapabilityToken?
  private var phase: Phase

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(
        x25519: TLS13X25519ClientKeyExchange(privateKey: ephemeralKey)
      ),
      certificateValidator: certificateValidator,
      serverCertificateType: .x509,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(
        x25519: TLS13X25519ClientKeyExchange(privateKey: ephemeralKey)
      ),
      certificateValidator: nil,
      serverCertificateType: externalServerTrust.certificateType,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519: keyExchange),
      certificateValidator: certificateValidator,
      serverCertificateType: .x509,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519: keyExchange),
      certificateValidator: nil,
      serverCertificateType: externalServerTrust.certificateType,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(p256: keyExchange),
      certificateValidator: certificateValidator,
      serverCertificateType: .x509,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(p256: keyExchange),
      certificateValidator: nil,
      serverCertificateType: externalServerTrust.certificateType,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519MLKEM768: keyExchange),
      certificateValidator: certificateValidator,
      serverCertificateType: .x509,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    transportParameters: Span<UInt8>? = nil,
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    resumptionState: consuming TLS13ResumptionState? = nil,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration? = nil,
    echConfiguration: consuming ECHClientConfiguration? = nil,
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ClientKeyExchangeState(x25519MLKEM768: keyExchange),
      certificateValidator: nil,
      serverCertificateType: externalServerTrust.certificateType,
      clientIdentity: consume clientIdentity,
      externalClientCredential: externalClientCredential,
      applicationProtocols: applicationProtocols,
      transportParameters: transportParameters,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: consume resumptionState,
      earlyDataConfiguration: earlyDataConfiguration,
      echConfiguration: consume echConfiguration,
      handshakeEncoding: handshakeEncoding
    )
  }

  private init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13ClientKeyExchangeState,
    certificateValidator: (any TLS13ServerCertificateValidating)?,
    serverCertificateType: TLS13CertificateType,
    clientIdentity: consuming TLS13ClientIdentity?,
    externalClientCredential: TLS13ExternalClientCredential?,
    applicationProtocols: consuming ContiguousArray<TLS13ApplicationProtocol>,
    transportParameters: Span<UInt8>?,
    serverName: Span<UInt8>?,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite,
    resumptionState: consuming TLS13ResumptionState?,
    earlyDataConfiguration: TLS13EarlyDataClientConfiguration?,
    echConfiguration: consuming ECHClientConfiguration?,
    handshakeEncoding: TLS13HandshakeEncoding
  ) throws(TLS13HandshakeEngineError) {
    guard random.count == 32 else {
      throw .invalidConfiguration
    }
    let selectsExternalClientCredential: Bool
    switch externalClientCredential {
    case .some: selectsExternalClientCredential = true
    case .none: selectsExternalClientCredential = false
    }
    guard
      !selectsExternalClientCredential
        || !containsClientIdentity(clientIdentity)
    else {
      throw .invalidConfiguration
    }
    guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
      throw .unsupportedCipherSuite(cipherSuite.rawValue)
    }
    guard earlyDataConfiguration == nil || handshakeEncoding != .dtls13 else {
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
    self.certificateValidator = certificateValidator
    configuredServerCertificateType = serverCertificateType
    configuredClientCertificateType = externalClientCredential?.certificateType
      ?? .x509
    offersPostHandshakeAuthentication = true
    self.clientIdentity = consume clientIdentity
    usesExternalClientCredential = selectsExternalClientCredential
    selectedExternalClientCredential = nil
    self.applicationProtocols = applicationProtocols
    if let transportParameters {
      localTransportParameters = OwnedBytes(copying: transportParameters)
    } else {
      localTransportParameters = nil
    }
    self.validatedServerPublicKey = nil
    echMaximumNameLength = echConfiguration?.selectedConfiguration.config.maximumNameLength
    echOuterRandom = echConfiguration?.outerRandom
    echPublicName = echConfiguration?.publicName
    self.verificationInstant = verificationInstant
    self.cipherSuite = cipherSuite
    self.handshakeEncoding = handshakeEncoding
    localConnectionID = nil
    expectedPeerConnectionID = nil
    srtpConfiguration = nil
    negotiatedSRTPProtectionProfile = nil
    negotiatedSRTPMasterKeyIdentifier = nil
    self.resumptionState = resumptionState
    self.earlyDataConfiguration = earlyDataConfiguration
    self.echConfiguration = consume echConfiguration
    echInnerClientHello = nil
    echOuterClientHello = nil
    retryClientHello = nil
    echAcceptanceConfirmedByRetry = false
    echWasRejected = false
    echRetryConfigurations = nil
    resumptionPSK = nil
    offeredResumption = false
    resumedHandshake = false
    earlyDataStateStorage = .notRequested
    earlyDataByteLimitStorage = 0
    handshakeSecrets = nil
    applicationSecrets = nil
    resumptionMasterSecret = nil
    sawEncryptedExtensions = false
    certificateRequest = nil
    sawCertificate = false
    sawCertificateVerify = false
    negotiatedServerCertificateType = .x509
    negotiatedClientCertificateType = .x509
    certificateCompression = nil
    selectedApplicationProtocol = nil
    peerTransportParameters = nil
    capabilitySequencer = TLS13CapabilitySequencer(
      random: random,
      role: .client
    )
    pendingServerTrust = nil
    pendingClientCredentialSelection = nil
    pendingClientSignature = nil
    pendingClientEndOfEarlyData = nil
    postHandshakeTranscript = nil
    postHandshakeRequest = nil
    postHandshakeCredential = nil
    postHandshakeFlightPrefix = []
    postHandshakeSignedMessage = nil
    pendingPostHandshakeCapabilityToken = nil
    phase = .idle
  }

  public var isEstablished: Bool {
    if case .established = phase { return true }
    return false
  }

  public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
    selectedApplicationProtocol
  }

  public var earlyDataState: TLS13EarlyDataState {
    earlyDataStateStorage
  }

  public var earlyDataByteLimit: UInt32 {
    earlyDataByteLimitStorage
  }

  public var receivedTransportParameters: OwnedBytes? {
    peerTransportParameters
  }

  /// Replaces the QUIC transport parameters before the client emits
  /// ClientHello. QUIC owns the configuration value, while this core owns the
  /// encoded bytes once the session is constructed.
  public mutating func configureTransportParameters(
    _ parameters: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) {
    guard case .idle = phase else {
      throw .invalidState
    }
    localTransportParameters = OwnedBytes(copying: parameters)
  }

  public var srtpProtectionProfile: DTLSSRTPProtectionProfile? {
    guard isEstablished else { return nil }
    return negotiatedSRTPProtectionProfile
  }

  public var srtpMasterKeyIdentifier: OwnedBytes? {
    guard isEstablished else { return nil }
    return negotiatedSRTPMasterKeyIdentifier
  }

  /// Configures the algorithms this endpoint can use to decompress peer
  /// certificates and to compress its own certificate when requested.
  public mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(TLS13HandshakeEngineError) {
    guard case .idle = phase else { throw .invalidState }
    certificateCompression = configuration
  }

  private var advertisedCertificateCompressionAlgorithms:
    ContiguousArray<TLS13CertificateCompressionAlgorithm>
  {
    certificateCompression?.algorithms ?? []
  }

  private var advertisedDelegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme>
  {
    configuredServerCertificateType == .x509
      ? [.ecdsaP256SHA256, .ed25519] : []
  }

  private var advertisedServerCertificateTypes:
    ContiguousArray<TLS13CertificateType>
  {
    configuredServerCertificateType == .x509
      ? [] : [configuredServerCertificateType]
  }

  private var advertisedClientCertificateTypes:
    ContiguousArray<TLS13CertificateType>
  {
    configuredClientCertificateType == .x509
      ? [] : [configuredClientCertificateType]
  }

  package mutating func configureDTLSConnectionIDs(
    local: OwnedBytes,
    expectedPeer: OwnedBytes
  ) throws(TLS13HandshakeEngineError) {
    guard handshakeEncoding == .dtls13,
      local.count <= UInt8.max, expectedPeer.count <= UInt8.max
    else {
      throw .invalidConfiguration
    }
    guard case .idle = phase else { throw .invalidState }
    localConnectionID = local
    expectedPeerConnectionID = expectedPeer
  }

  package mutating func configureDTLSSRTP(
    _ configuration: DTLSSRTPClientConfiguration
  ) throws(TLS13HandshakeEngineError) {
    guard handshakeEncoding == .dtls13 else {
      throw .invalidConfiguration
    }
    guard case .idle = phase else { throw .invalidState }
    srtpConfiguration = configuration
  }

  public mutating func start()
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput
  {
    guard case .idle = phase else { throw .invalidState }
    do {
      let namedGroup = keyExchange.namedGroup
      let srtpOffer = makeDTLSSRTPOffer()
      let clientHello = try keyExchange.withClientShare { keyShare in
        let clientHello: OwnedBytes
        if var state = resumptionState.take() {
          guard state.cipherSuite == cipherSuite else {
            throw TLS13HandshakeEngineError.invalidConfiguration
          }
          let psk = try state.consumePSK()
          let offersEarlyData: Bool
          if let earlyDataConfiguration {
            guard state.maximumEarlyDataByteCount > 0 else {
              throw TLS13HandshakeEngineError.invalidConfiguration
            }
            let protocolMatches: Bool
            if let ticketProtocol = state.applicationProtocol {
              protocolMatches = applicationProtocols.contains(ticketProtocol)
            } else {
              protocolMatches = applicationProtocols.isEmpty
            }
            guard protocolMatches else {
              throw TLS13HandshakeEngineError.invalidConfiguration
            }
            offersEarlyData = true
            earlyDataStateStorage = .offered
            earlyDataByteLimitStorage = Swift.min(
              state.maximumEarlyDataByteCount,
              earlyDataConfiguration.maximumByteCount
            )
          } else {
            offersEarlyData = false
          }
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
            clientCertificateTypes: advertisedClientCertificateTypes,
            serverCertificateTypes: advertisedServerCertificateTypes,
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            applicationProtocols: applicationProtocols,
            transportParameters: localTransportParameters?.span,
            connectionID: localConnectionID?.span,
            useSRTP: srtpOffer,
            offersPostHandshakeAuthentication:
              offersPostHandshakeAuthentication,
            offersEarlyData: offersEarlyData,
            preSharedKey: zeroExtension,
            encoding: handshakeEncoding
          )
          let actualBinder = try makeResumptionBinder(
            preSharedKey: psk,
            cipherSuite: cipherSuite,
            zeroClientHello: zeroHello.span,
            echMaximumNameLength: echMaximumNameLength,
            handshakeEncoding: handshakeEncoding
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
            clientCertificateTypes: advertisedClientCertificateTypes,
            serverCertificateTypes: advertisedServerCertificateTypes,
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            applicationProtocols: applicationProtocols,
            transportParameters: localTransportParameters?.span,
            connectionID: localConnectionID?.span,
            useSRTP: srtpOffer,
            offersPostHandshakeAuthentication:
              offersPostHandshakeAuthentication,
            offersEarlyData: offersEarlyData,
            preSharedKey: actualExtension,
            encoding: handshakeEncoding
          )
          resumptionPSK = consume psk
          offeredResumption = true
        } else {
          guard earlyDataConfiguration == nil else {
            throw TLS13HandshakeEngineError.invalidConfiguration
          }
          clientHello = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            namedGroup: namedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: serverName,
            clientCertificateTypes: advertisedClientCertificateTypes,
            serverCertificateTypes: advertisedServerCertificateTypes,
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            applicationProtocols: applicationProtocols,
            transportParameters: localTransportParameters?.span,
            connectionID: localConnectionID?.span,
            useSRTP: srtpOffer,
            offersPostHandshakeAuthentication:
              offersPostHandshakeAuthentication,
            encoding: handshakeEncoding
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
            serverName: publicName,
            clientCertificateTypes: advertisedClientCertificateTypes,
            serverCertificateTypes: advertisedServerCertificateTypes,
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            applicationProtocols: applicationProtocols,
            transportParameters: localTransportParameters?.span,
            connectionID: localConnectionID?.span,
            useSRTP: srtpOffer,
            offersPostHandshakeAuthentication:
              offersPostHandshakeAuthentication,
            encoding: handshakeEncoding
          )
        }
        let offer = try configuration.seal(
          innerClientHello: clientHello.span,
          outerClientHello: outerTemplate.span,
          encoding: handshakeEncoding
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
    // A retry needs the exact first ClientHello, including unknown extensions.
    // Retention is limited to the handshake lifetime and does not add a copy to
    // the application-data path.
    retryClientHello = transcriptClientHello
    try appendTranscript(transcriptClientHello.span)
    phase = .awaitingServerHello
    if earlyDataStateStorage == .offered {
      guard resumptionPSK != nil else { throw .invalidState }
      let transcriptHash = try transcriptDigest()
      let schedule: TLS13KeySchedule
      do {
        schedule = try resumptionPSK!.withBorrowedBytes { psk in
          try TLS13KeySchedule(cipherSuite: cipherSuite, preSharedKey: psk)
        }
      } catch {
        throw mapHandshakeEngineError(error)
      }
      let earlySecret: TLS13EarlyTrafficSecret
      do {
        earlySecret = try schedule.makeClientEarlyTrafficSecret(
          transcriptHash: transcriptHash.span
        )
      } catch let error {
        throw .keySchedule(error)
      }
      let range: ByteRange
      do {
        range = try ByteRange(offset: 0, count: wireClientHello.count)
      } catch let error {
        throw .output(error)
      }
      return try makeOutput(
        bytes: wireClientHello,
        actions: [
          .emitHandshakeBytes(epoch: .initial, bytes: range),
          .installEarlyTrafficSecret(disposition: .application),
        ],
        earlyTrafficSecret: earlySecret
      )
    }
    return try makeEmission(wireClientHello, at: .initial)
  }

  public mutating func receiveHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    if certificateValidator == nil,
      case .awaitingServerFlight = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateType
        || message[0] == TLS13HandshakeCodec.compressedCertificateType
    {
      throw .capability(.wrongState)
    }
    if usesExternalClientCredential,
      certificateRequest != nil,
      case .awaitingServerFlight = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.finishedType
    {
      throw .capability(.wrongState)
    }
    do {
      switch phase {
      case .awaitingServerHello:
        guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
        if try TLS13HandshakeCodec.isHelloRetryRequest(
          message,
          encoding: handshakeEncoding
        ) {
          return try receiveHelloRetryRequest(message)
        }
        return try receiveServerHello(message)
      case .awaitingServerHelloAfterRetry:
        guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
        if try TLS13HandshakeCodec.isHelloRetryRequest(
          message,
          encoding: handshakeEncoding
        ) {
          throw TLS13HandshakeEngineError.handshake(
            .unexpectedMessage(type: TLS13HandshakeCodec.serverHelloType)
          )
        }
        return try receiveServerHello(message)
      case .awaitingServerFlight:
        guard epoch == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveServerFlightMessage(message)
      case .idle, .suspendedForPeerTrust, .suspendedForCredentialSelection,
        .suspendedForSignature,
        .suspendedForPostHandshakeCredentialSelection,
        .suspendedForPostHandshakeSignature, .established, .failed:
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

  /// Advances the core or returns one terminal external-capability request.
  public mutating func receiveHandshakeMessageStep(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    if case .established = phase,
      epoch == .application,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateRequestType
    {
      return try receivePostHandshakeAuthenticationRequestStep(message)
    }
    if certificateValidator == nil,
      case .awaitingServerFlight = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateType
        || message[0] == TLS13HandshakeCodec.compressedCertificateType
    {
      do {
        return .suspended(try suspendForServerTrust(message))
      } catch let error {
        phase = .failed
        throw error
      }
    }
    if usesExternalClientCredential,
      certificateRequest != nil,
      case .awaitingServerFlight = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.finishedType
    {
      do {
        return try suspendForClientCredentialSelection(message)
      } catch let error as TLS13HandshakeEngineError {
        phase = .failed
        throw error
      } catch {
        phase = .failed
        throw mapHandshakeEngineError(error)
      }
    }
    return .output(try receiveHandshakeMessage(message, at: epoch))
  }

  /// Responds to one RFC 8446 post-handshake CertificateRequest.
  public mutating func receivePostHandshakeAuthenticationRequestStep(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard case .established = phase,
      offersPostHandshakeAuthentication,
      applicationSecrets != nil,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateRequestType,
      postHandshakeTranscript == nil,
      pendingPostHandshakeCapabilityToken == nil
    else {
      throw .invalidState
    }
    do {
      let request = try TLS13HandshakeCodec.parseCertificateRequest(message)
      guard !request.requestContext.isEmpty else {
        throw TLS13HandshakeEngineError.malformedInput
      }
      var authenticationTranscript = transcript.clone()
      try authenticationTranscript.append(message)

      if usesExternalClientCredential {
        let token = try capabilitySequencer.issue(kind: .credentialSelection)
        postHandshakeTranscript = consume authenticationTranscript
        postHandshakeRequest = request
        pendingPostHandshakeCapabilityToken = token
        phase = .suspendedForPostHandshakeCredentialSelection
        return .suspended(
          .credentialSelection(
            TLS13CredentialSelectionRequest(
              token: token,
              role: .client,
              serverName: serverName,
              signatureSchemes: request.signatureSchemes,
              delegatedCredentialAlgorithms:
                request.delegatedCredentialAlgorithms,
              certificateTypes: [negotiatedClientCertificateType],
              certificateRequestContext: request.requestContext,
              verificationInstant: verificationInstant
            )
          )
        )
      }

      let activeIdentity = clientIdentity.take()
      var messages = ContiguousArray<OwnedBytes>()
      switch consume activeIdentity {
      case .some(let identity) where certificateRequest(request, supports: identity):
        let uncompressed = try TLS13HandshakeCodec.makeCertificate(
          entries: identity.certificateEntries,
          requestContext: request.requestContext.span
        )
        let certificate = try compressCertificateMessageIfUseful(
          uncompressed,
          peerAlgorithms: request.certificateCompressionAlgorithms
        )
        try authenticationTranscript.append(certificate.span)
        messages.append(certificate)
        let certificateHash = try authenticationTranscript.digest(
          for: cipherSuite
        )
        let signed = TLS13HandshakeWire.certificateVerifyInput(
          role: .client,
          transcriptHash: certificateHash.span
        )
        let signature = try identity.sign(message: signed.span)
        let certificateVerify = try makeCertificateVerifyMessage(
          signatureScheme: identity.signatureScheme,
          signature: signature
        )
        try authenticationTranscript.append(certificateVerify.span)
        messages.append(certificateVerify)
        clientIdentity = consume identity

      case .some(let unsupportedIdentity):
        let certificate = try makeEmptyClientCertificate(
          requestContext: request.requestContext.span
        )
        try authenticationTranscript.append(certificate.span)
        messages.append(certificate)
        clientIdentity = consume unsupportedIdentity

      case .none:
        let certificate = try makeEmptyClientCertificate(
          requestContext: request.requestContext.span
        )
        try authenticationTranscript.append(certificate.span)
        messages.append(certificate)
      }
      return .output(
        try finalizePostHandshakeClientAuthentication(
          messages: messages,
          transcript: consume authenticationTranscript
        )
      )
    } catch let error as TLS13HandshakeEngineError {
      phase = .failed
      throw error
    } catch let error as TLS13HandshakeError {
      phase = .failed
      throw .handshake(error)
    } catch let error as TLS13SigningError {
      phase = .failed
      throw .signing(error)
    } catch let error as TLS13CapabilityError {
      phase = .failed
      throw .capability(error)
    } catch {
      phase = .failed
      throw mapHandshakeEngineError(error)
    }
  }

  /// Resumes exactly one pending external capability operation.
  public mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    do {
      try capabilitySequencer.validate(
        response,
        pending: pendingCapabilityToken()
      )
    } catch let error {
      throw .capability(error)
    }

    switch phase {
    case .suspendedForPeerTrust:
      return try resumeServerTrust(response)
    case .suspendedForCredentialSelection:
      return try resumeClientCredentialSelection(response)
    case .suspendedForSignature:
      return try resumeClientSignature(response)
    case .suspendedForPostHandshakeCredentialSelection:
      return try resumePostHandshakeCredentialSelection(response)
    case .suspendedForPostHandshakeSignature:
      return try resumePostHandshakeSignature(response)
    default:
      throw .capability(.wrongState)
    }
  }

  private mutating func resumeServerTrust(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingServerTrust else {
      throw .capability(.wrongState)
    }

    switch response {
    case .peerTrustRejected(let token):
      capabilitySequencer.complete(token)
      pendingServerTrust = nil
      phase = .failed
      throw .capability(.peerTrustRejected(.server))

    case .peerTrustAccepted(let token):
      do {
        let subjectPublicKeyInfo = try
          TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
            for: pending.certificateMessage,
            role: .server,
            signatureSchemes:
              TLS13DelegatedCredentialProcessor.signatureSchemes,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            at: verificationInstant
          )
        validatedServerPublicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: subjectPublicKeyInfo
        )
        try appendTranscript(pending.encodedMessage.span)
        sawCertificate = true
        capabilitySequencer.complete(token)
        pendingServerTrust = nil
        phase = .awaitingServerFlight
        return .output(try makeEmptyOutput())
      } catch let error as TLS13HandshakeEngineError {
        pendingServerTrust = nil
        phase = .failed
        throw error
      } catch let error as X509CertificateError {
        pendingServerTrust = nil
        phase = .failed
        throw .certificate(error)
      } catch {
        pendingServerTrust = nil
        phase = .failed
        throw .certificateVerificationFailed
      }
    case .credentialSelected, .credentialUnavailable, .signature,
      .signatureRejected:
      throw .capability(.wrongState)
    }
  }

  private borrowing func pendingCapabilityToken() -> TLS13CapabilityToken? {
    switch phase {
    case .suspendedForPeerTrust:
      pendingServerTrust?.token
    case .suspendedForCredentialSelection:
      pendingClientCredentialSelection?.token
    case .suspendedForSignature:
      pendingClientSignature?.token
    case .suspendedForPostHandshakeCredentialSelection,
      .suspendedForPostHandshakeSignature:
      pendingPostHandshakeCapabilityToken
    default:
      nil
    }
  }

  private mutating func suspendForServerTrust(
    _ encodedMessage: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest {
    guard case .awaitingServerFlight = phase,
      sawEncryptedExtensions,
      !resumedHandshake,
      !sawCertificate,
      pendingServerTrust == nil
    else {
      throw .invalidState
    }
    let certificateMessage = try parsePeerCertificateMessage(encodedMessage)
    guard certificateMessage.requestContext.isEmpty,
      !certificateMessage.entries.isEmpty
    else {
      throw .certificateVerificationFailed
    }
    let authenticatedName: OwnedBytes?
    if echWasRejected {
      guard let publicName = echPublicName else { throw .invalidConfiguration }
      authenticatedName = publicName
    } else {
      authenticatedName = serverName
    }
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .peerTrustEvaluation)
    } catch let error {
      throw .capability(error)
    }
    pendingServerTrust = PendingServerTrust(
      token: token,
      encodedMessage: OwnedBytes(copying: encodedMessage),
      certificateMessage: certificateMessage
    )
    phase = .suspendedForPeerTrust
    return .peerTrustEvaluation(
      TLS13PeerTrustEvaluationRequest(
        token: token,
        peer: .server,
        certificateMessage: certificateMessage,
        serverName: authenticatedName,
        verificationInstant: verificationInstant
      )
    )
  }

  private mutating func receiveHelloRetryRequest(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let retry = try engineTry {
      try TLS13HandshakeCodec.parseHelloRetryRequest(
        message,
        encoding: handshakeEncoding
      )
    }
    guard retry.cipherSuite == cipherSuite else {
      throw .unsupportedCipherSuite(retry.cipherSuite.rawValue)
    }
    guard let firstClientHello = retryClientHello else {
      throw .invalidState
    }

    let retryBase: OwnedBytes
    let echAccepted: Bool
    if let innerClientHello = echInnerClientHello {
      do {
        echAccepted = try ECHAcceptanceConfirmation
          .isHelloRetryRequestAccepted(
            innerClientHello: innerClientHello.span,
            helloRetryRequest: message,
            cipherSuite: cipherSuite,
            handshakeEncoding: handshakeEncoding
          )
      } catch let error {
        throw .ech(error)
      }
      if echAccepted {
        retryBase = innerClientHello
        echWasRejected = false
        echAcceptanceConfirmedByRetry = true
      } else {
        guard let outerClientHello = echOuterClientHello else {
          throw .invalidState
        }
        do {
          transcript = try TLS13Transcript()
          try transcript.append(outerClientHello.span)
        } catch let error {
          throw .handshake(error)
        }
        retryBase = outerClientHello
        echWasRejected = true
        echAcceptanceConfirmedByRetry = false
      }
    } else {
      guard retry.echAcceptanceConfirmation == nil else {
        throw .ech(.invalidClientHello)
      }
      retryBase = firstClientHello
      echAccepted = false
    }

    do {
      try transcript.replaceWithMessageHash(for: cipherSuite)
      try transcript.append(message)
    } catch let error {
      throw .handshake(error)
    }
    var secondClientHello = try clientHelloByAddingRetryCookie(
      to: retryBase,
      cookie: retry.cookie
    )
    if earlyDataStateStorage == .offered {
      secondClientHello = try engineTry {
        try TLS13HandshakeCodec.clientHelloByRemovingEarlyData(
          secondClientHello.span,
          encoding: handshakeEncoding
        )
      }
      earlyDataStateStorage = .rejected
    }
    let parsedSecond = try engineTry {
      try TLS13HandshakeCodec.parseClientHello(
        secondClientHello.span,
        encoding: handshakeEncoding
      )
    }
    if parsedSecond.preSharedKey != nil {
      guard offeredResumption, resumptionPSK != nil else {
        throw .invalidState
      }
      let truncated = try engineTry {
        try TLS13HandshakeCodec.truncatedClientHelloForBinder(
          secondClientHello.span,
          encoding: handshakeEncoding
        )
      }
      let binderHash: OwnedBytes
      do {
        binderHash = try transcript.digest(
          appending: truncated.span,
          for: cipherSuite
        )
      } catch let error {
        throw .handshake(error)
      }
      let binder: TLS13PSKBinder
      do {
        binder = try makeBinder(
          preSharedKey: resumptionPSK!,
          cipherSuite: cipherSuite,
          transcriptHash: binderHash.span
        )
      } catch {
        throw mapHandshakeEngineError(error)
      }
      secondClientHello = try engineTry {
        try TLS13HandshakeCodec.clientHelloByReplacingPSKBinders(
          secondClientHello.span,
          binders: [binder],
          encoding: handshakeEncoding
        )
      }
    }

    let srtpOffer = makeDTLSSRTPOffer()
    if echAccepted {
      guard var configuration = echConfiguration.take(),
        let outerRandom = echOuterRandom,
        let publicName = echPublicName
      else {
        throw .invalidState
      }
      let retryNamedGroup = keyExchange.namedGroup
      let outerTemplate: OwnedBytes
      do {
        outerTemplate = try keyExchange.withClientShare { keyShare in
          let base = try TLS13HandshakeCodec.makeClientHello(
            random: outerRandom.span,
            namedGroup: retryNamedGroup,
            keyShare: keyShare,
            cipherSuite: cipherSuite,
            serverName: publicName,
            clientCertificateTypes: advertisedClientCertificateTypes,
            serverCertificateTypes: advertisedServerCertificateTypes,
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms,
            applicationProtocols: applicationProtocols,
            transportParameters: localTransportParameters?.span,
            connectionID: localConnectionID?.span,
            useSRTP: srtpOffer,
            offersPostHandshakeAuthentication:
              offersPostHandshakeAuthentication,
            encoding: handshakeEncoding
          )
          return try TLS13HandshakeCodec.clientHelloByAddingCookie(
            base.span,
            cookie: retry.cookie.span,
            encoding: handshakeEncoding
          )
        }
      } catch {
        echConfiguration = consume configuration
        throw mapHandshakeEngineError(error)
      }
      let offer: ECHClientHelloOffer
      do {
        offer = try configuration.seal(
          innerClientHello: secondClientHello.span,
          outerClientHello: outerTemplate.span,
          encoding: handshakeEncoding
        )
      } catch let error {
        echConfiguration = consume configuration
        throw .ech(error)
      }
      echConfiguration = consume configuration
      echInnerClientHello = offer.innerClientHello
      echOuterClientHello = offer.outerClientHello
      return try finishHelloRetryRequest(
        transcriptClientHello: offer.innerClientHello,
        wireClientHello: offer.outerClientHello
      )
    }
    if echWasRejected {
      echOuterClientHello = secondClientHello
    }
    return try finishHelloRetryRequest(
      transcriptClientHello: secondClientHello,
      wireClientHello: secondClientHello
    )
  }

  private func clientHelloByAddingRetryCookie(
    to base: OwnedBytes,
    cookie: OwnedBytes
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    do {
      return try base.withBorrowedBytes {
        baseBytes throws(TLS13HandshakeError) in
        try cookie.withBorrowedBytes {
          cookieBytes throws(TLS13HandshakeError) in
          try TLS13HandshakeCodec.clientHelloByAddingCookie(
            baseBytes,
            cookie: cookieBytes,
            encoding: handshakeEncoding
          )
        }
      }
    } catch let error {
      throw .handshake(error)
    }
  }

  private mutating func finishHelloRetryRequest(
    transcriptClientHello: OwnedBytes,
    wireClientHello: consuming OwnedBytes
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    try appendTranscript(transcriptClientHello.span)
    retryClientHello = transcriptClientHello
    phase = .awaitingServerHelloAfterRetry
    let range: ByteRange
    do {
      range = try ByteRange(offset: 0, count: wireClientHello.count)
    } catch let error {
      throw .output(error)
    }
    var actions: ContiguousArray<TLS13HandshakeCoreAction> = [
      .emitHandshakeBytes(epoch: .initial, bytes: range)
    ]
    if earlyDataStateStorage == .rejected {
      actions.append(.earlyDataRejected)
    }
    return try makeOutput(bytes: wireClientHello, actions: actions)
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

  /// Advances a QUIC 1-RTT traffic secret using RFC 9001's `quic ku` label.
  public mutating func updateQUICApplicationTrafficSecret(
    for endpoint: TLSRole
  ) throws(TLS13HandshakeEngineError) -> TLS13TrafficSecret {
    guard case .established = phase,
      var secrets = applicationSecrets.take()
    else {
      throw .invalidState
    }
    do {
      switch endpoint {
      case .client: try secrets.updateQUICClientTrafficSecret()
      case .server: try secrets.updateQUICServerTrafficSecret()
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
          ageAdd: ticket.ageAdd,
          maximumEarlyDataByteCount: ticket.maximumEarlyDataByteCount ?? 0,
          applicationProtocol: selectedApplicationProtocol
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
      try TLS13HandshakeCodec.parseServerHello(
        message,
        encoding: handshakeEncoding
      )
    }
    if let expectedPeerConnectionID {
      guard serverHello.connectionID == expectedPeerConnectionID else {
        throw .invalidConfiguration
      }
    } else if serverHello.connectionID != nil {
      throw .invalidConfiguration
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
      if echWasRejected {
        guard !serverHello.selectedPreSharedKey else {
          throw .ech(.invalidClientHello)
        }
        try appendTranscript(message)
      } else {
        let accepted: Bool
        do {
          accepted = try ECHAcceptanceConfirmation.isAccepted(
            innerClientHello: innerClientHello.span,
            serverHello: message,
            cipherSuite: cipherSuite,
            handshakeEncoding: handshakeEncoding
          )
        } catch let error {
          throw .ech(error)
        }
        if accepted {
          echWasRejected = false
          echOuterClientHello = nil
          try appendTranscript(message)
        } else {
          guard !echAcceptanceConfirmedByRetry else {
            throw .ech(.invalidClientHello)
          }
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
      let encryptedExtensions = try engineTry {
        try TLS13HandshakeCodec.parseEncryptedExtensions(
          message,
          encoding: handshakeEncoding
        )
      }
      let selectedServerCertificateType =
        encryptedExtensions.serverCertificateType ?? .x509
      guard selectedServerCertificateType == configuredServerCertificateType else {
        throw .certificateVerificationFailed
      }
      if configuredServerCertificateType != .x509 {
        guard encryptedExtensions.serverCertificateType != nil else {
          throw .certificateVerificationFailed
        }
      }
      negotiatedServerCertificateType = selectedServerCertificateType
      let selectedClientCertificateType =
        encryptedExtensions.clientCertificateType ?? .x509
      guard selectedClientCertificateType == configuredClientCertificateType else {
        throw .certificateVerificationFailed
      }
      if configuredClientCertificateType != .x509 {
        guard encryptedExtensions.clientCertificateType != nil else {
          throw .certificateVerificationFailed
        }
      }
      negotiatedClientCertificateType = selectedClientCertificateType
      try validateDTLSSRTP(selection: encryptedExtensions.useSRTP)
      let retryConfigurations = encryptedExtensions.echRetryConfigurations
      if echInnerClientHello != nil {
        if echWasRejected {
          echRetryConfigurations = retryConfigurations
        } else if retryConfigurations != nil {
          throw .ech(.invalidClientHello)
        }
      } else if retryConfigurations != nil {
        throw .ech(.invalidClientHello)
      }
      if applicationProtocols.isEmpty {
        guard encryptedExtensions.applicationProtocol == nil else {
          throw .applicationProtocol(.noApplicationProtocol)
        }
      } else {
        guard let selected = encryptedExtensions.applicationProtocol,
          applicationProtocols.contains(selected)
        else {
          throw .applicationProtocol(.noApplicationProtocol)
        }
        selectedApplicationProtocol = selected
      }
      switch (
        localTransportParameters,
        encryptedExtensions.peerTransportParameters
      ) {
      case (.none, .none):
        break
      case (.some, .some(let received)):
        peerTransportParameters = received
      case (.some, .none):
        throw .missingTransportParameters
      case (.none, .some):
        throw .unexpectedTransportParameters
      }
      var actions = ContiguousArray<TLS13HandshakeCoreAction>()
      if encryptedExtensions.acceptsEarlyData {
        guard earlyDataStateStorage == .offered,
          resumedHandshake,
          handshakeEncoding != .dtls13
        else {
          throw .malformedInput
        }
        earlyDataStateStorage = .accepted
        actions.append(.earlyDataAccepted)
      } else if earlyDataStateStorage == .offered {
        earlyDataStateStorage = .rejected
        actions.append(.earlyDataRejected)
      }
      try appendTranscript(message)
      sawEncryptedExtensions = true
      return try makeEmptyOutput(actions: actions)

    case TLS13HandshakeCodec.certificateRequestType:
      guard !resumedHandshake,
        sawEncryptedExtensions,
        certificateRequest == nil,
        !sawCertificate
      else {
        throw .malformedInput
      }
      let request = try engineTry {
        try TLS13HandshakeCodec.parseCertificateRequest(message)
      }
      guard request.requestContext.isEmpty else {
        throw .malformedInput
      }
      try appendTranscript(message)
      certificateRequest = request
      return try makeEmptyOutput()

    case TLS13HandshakeCodec.certificateType,
      TLS13HandshakeCodec.compressedCertificateType:
      guard !resumedHandshake, sawEncryptedExtensions, !sawCertificate else {
        throw .malformedInput
      }
      let certificateMessage = try parsePeerCertificateMessage(message)
      guard certificateMessage.requestContext.isEmpty,
        !certificateMessage.entries.isEmpty
      else {
        throw .certificateVerificationFailed
      }
      let authenticatedName: OwnedBytes?
      if echWasRejected {
        guard let publicName = echPublicName else {
          throw .invalidConfiguration
        }
        authenticatedName = publicName
      } else {
        authenticatedName = serverName
      }

      guard negotiatedServerCertificateType == .x509,
        let certificateValidator
      else {
        throw .capability(.wrongState)
      }
      let validatedSubjectPublicKeyInfo: SubjectPublicKeyInfo
      do {
        if let authenticatedName {
          validatedSubjectPublicKeyInfo = try authenticatedName.withBorrowedBytes {
            serverName throws(TLS13ServerCertificateValidationError) in
            try certificateValidator.validate(
              certificateMessage,
              serverName: serverName,
              at: verificationInstant
            )
          }
        } else {
          validatedSubjectPublicKeyInfo = try certificateValidator.validate(
            certificateMessage,
            serverName: nil,
            at: verificationInstant
          )
        }
      } catch let error {
        throw .certificateValidation(error)
      }
      do {
        let activeSubjectPublicKeyInfo: SubjectPublicKeyInfo
        if certificateMessage.entries.first?.delegatedCredential != nil {
          activeSubjectPublicKeyInfo = try
            TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
              for: certificateMessage,
              role: .server,
              signatureSchemes:
                TLS13DelegatedCredentialProcessor.signatureSchemes,
              delegatedCredentialAlgorithms:
                advertisedDelegatedCredentialAlgorithms,
              at: verificationInstant
            )
        } else {
          activeSubjectPublicKeyInfo = validatedSubjectPublicKeyInfo
        }
        validatedServerPublicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: activeSubjectPublicKeyInfo
        )
      } catch let error as TLS13HandshakeEngineError {
        throw error
      } catch {
        throw .certificateVerificationFailed
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
      let hash = try transcriptDigest()
      let signed = TLS13HandshakeWire.certificateVerifyInput(
        role: .server,
        transcriptHash: hash.span
      )
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
    let endOfEarlyData = try processServerFinished(message)
    let activeClientIdentity = clientIdentity.take()
    var clientFlightMessages = ContiguousArray<OwnedBytes>()
    if let request = certificateRequest {
      switch consume activeClientIdentity {
      case .some(let identity)
        where certificateRequest(request, supports: identity):
        let uncompressedCertificateMessage = try engineTry {
          try TLS13HandshakeCodec.makeCertificate(
            entries: identity.certificateEntries,
            requestContext: request.requestContext.span
          )
        }
        let certificateMessage = try compressCertificateMessageIfUseful(
          uncompressedCertificateMessage,
          peerAlgorithms: request.certificateCompressionAlgorithms
        )
        try appendTranscript(certificateMessage.span)
        clientFlightMessages.append(certificateMessage)
        let certificateHash = try transcriptDigest()
        let signed = TLS13HandshakeWire.certificateVerifyInput(
          role: .client,
          transcriptHash: certificateHash.span
        )
        let signature = try engineTry {
          try identity.sign(message: signed.span)
        }
        let certificateVerify = try makeCertificateVerifyMessage(
          signatureScheme: identity.signatureScheme,
          signature: signature
        )
        try appendTranscript(certificateVerify.span)
        clientFlightMessages.append(certificateVerify)
        clientIdentity = consume identity

      case .some(let unsupportedIdentity):
        _ = unsupportedIdentity.signatureScheme
        let certificateMessage = try makeEmptyClientCertificate(
          requestContext: request.requestContext.span
        )
        try appendTranscript(certificateMessage.span)
        clientFlightMessages.append(certificateMessage)
        clientIdentity = consume unsupportedIdentity

      case .none:
        let certificateMessage = try makeEmptyClientCertificate(
          requestContext: request.requestContext.span
        )
        try appendTranscript(certificateMessage.span)
        clientFlightMessages.append(certificateMessage)
      }
    } else {
      switch consume activeClientIdentity {
      case .some(let identity):
        clientIdentity = consume identity
      case .none:
        break
      }
    }
    return try finalizeClientFlight(
      endOfEarlyData: endOfEarlyData,
      messages: clientFlightMessages
    )
  }

  private mutating func processServerFinished(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes? {
    let finished = try engineTry {
      try TLS13HandshakeCodec.parseFinished(
        message,
        hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
      )
    }
    let verificationHash = try transcriptDigest()
    guard handshakeSecrets != nil else { throw .invalidState }
    let expected: OwnedBytes
    do {
      expected = try handshakeSecrets!.makeServerFinishedVerifyData(
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
    let derived: TLS13ApplicationSecrets
    do {
      derived = try handshakeSecrets!.makeApplicationSecrets(
        transcriptHash: applicationHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let endOfEarlyData: OwnedBytes?
    if earlyDataStateStorage == .accepted, handshakeEncoding == .tls13 {
      let message = try engineTry {
        try TLS13HandshakeCodec.makeEndOfEarlyData()
      }
      try appendTranscript(message.span)
      endOfEarlyData = message
    } else {
      endOfEarlyData = nil
    }
    applicationSecrets = consume derived
    return endOfEarlyData
  }

  private mutating func suspendForClientCredentialSelection(
    _ serverFinished: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard usesExternalClientCredential,
      selectedExternalClientCredential == nil,
      pendingClientCredentialSelection == nil,
      pendingClientSignature == nil,
      let request = certificateRequest
    else {
      throw .invalidState
    }
    let endOfEarlyData = try processServerFinished(serverFinished)
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .credentialSelection)
    } catch let error {
      throw .capability(error)
    }
    pendingClientCredentialSelection = PendingClientCredentialSelection(
      token: token,
      signatureSchemes: request.signatureSchemes,
      delegatedCredentialAlgorithms: request.delegatedCredentialAlgorithms,
      requestContext: request.requestContext
    )
    pendingClientEndOfEarlyData = endOfEarlyData
    phase = .suspendedForCredentialSelection
    return .suspended(
      .credentialSelection(
        TLS13CredentialSelectionRequest(
          token: token,
          role: .client,
          serverName: serverName,
          signatureSchemes: request.signatureSchemes,
          delegatedCredentialAlgorithms:
            request.delegatedCredentialAlgorithms,
          certificateTypes: [negotiatedClientCertificateType],
          certificateRequestContext: request.requestContext,
          verificationInstant: verificationInstant
        )
      )
    )
  }

  private mutating func resumeClientCredentialSelection(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingClientCredentialSelection else {
      throw .capability(.wrongState)
    }
    switch response {
    case .credentialUnavailable(let token):
      do {
        let certificateMessage = try makeEmptyClientCertificate(
          requestContext: pending.requestContext.span
        )
        try appendTranscript(certificateMessage.span)
        pendingClientCredentialSelection = nil
        let endOfEarlyData = pendingClientEndOfEarlyData.take()
        let output = try finalizeClientFlight(
          endOfEarlyData: endOfEarlyData,
          messages: [certificateMessage]
        )
        capabilitySequencer.complete(token)
        return .output(output)
      } catch let error as TLS13HandshakeEngineError {
        pendingClientCredentialSelection = nil
        pendingClientEndOfEarlyData = nil
        phase = .failed
        throw error
      } catch {
        pendingClientCredentialSelection = nil
        pendingClientEndOfEarlyData = nil
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .credentialSelected(let token, let credential):
      do {
        try validateExternalClientCredential(
          credential,
          offeredSignatureSchemes: pending.signatureSchemes,
          offeredDelegatedCredentialAlgorithms:
            pending.delegatedCredentialAlgorithms
        )
        let certificateMessage = try makeExternalCredentialCertificateMessage(
          credential,
          requestContext: pending.requestContext.span
        )
        let wireCertificateMessage = try compressCertificateMessageIfUseful(
          certificateMessage,
          peerAlgorithms: certificateRequest?
            .certificateCompressionAlgorithms ?? []
        )
        try appendTranscript(wireCertificateMessage.span)
        let certificateHash = try transcriptDigest()
        let signedMessage = TLS13HandshakeWire.certificateVerifyInput(
          role: .client,
          transcriptHash: certificateHash.span
        )
        let signatureToken: TLS13CapabilityToken
        do {
          signatureToken = try capabilitySequencer.issue(kind: .signature)
        } catch let error {
          throw TLS13HandshakeEngineError.capability(error)
        }
        selectedExternalClientCredential = credential
        pendingClientSignature = PendingClientSignature(
          token: signatureToken,
          flightPrefix: [wireCertificateMessage],
          signedMessage: signedMessage
        )
        pendingClientCredentialSelection = nil
        capabilitySequencer.complete(token)
        phase = .suspendedForSignature
        return .suspended(
          .signature(
            TLS13SignatureRequest(
              token: signatureToken,
              role: .client,
              credentialIdentifier: credential.identifier,
              signatureScheme: credential.signatureScheme,
              message: signedMessage
            )
          )
        )
      } catch let error as TLS13HandshakeEngineError {
        pendingClientCredentialSelection = nil
        pendingClientEndOfEarlyData = nil
        selectedExternalClientCredential = nil
        phase = .failed
        throw error
      } catch {
        pendingClientCredentialSelection = nil
        pendingClientEndOfEarlyData = nil
        selectedExternalClientCredential = nil
        phase = .failed
        throw .capability(.invalidCredential)
      }

    case .peerTrustAccepted, .peerTrustRejected, .signature,
      .signatureRejected:
      throw .capability(.wrongState)
    }
  }

  private mutating func resumeClientSignature(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingClientSignature,
      let credential = selectedExternalClientCredential
    else {
      throw .capability(.wrongState)
    }
    switch response {
    case .signatureRejected(let token):
      pendingClientSignature = nil
      pendingClientEndOfEarlyData = nil
      selectedExternalClientCredential = nil
      capabilitySequencer.complete(token)
      phase = .failed
      throw .capability(.signatureRejected(.client))

    case .signature(let token, let signature):
      pendingClientSignature = nil
      let endOfEarlyData = pendingClientEndOfEarlyData.take()
      do {
        let publicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: subjectPublicKeyInfo(for: credential)
        )
        let certificateVerifyValue = TLS13CertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature
        )
        guard
          try publicKey.verify(
            certificateVerifyValue,
            signedMessage: pending.signedMessage.span
          )
        else {
          throw TLS13HandshakeEngineError.certificateVerifyFailure
        }
        let certificateVerify = try TLS13HandshakeCodec.makeCertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature.span
        )
        try appendTranscript(certificateVerify.span)
        var messages = pending.flightPrefix
        messages.append(certificateVerify)
        let output = try finalizeClientFlight(
          endOfEarlyData: endOfEarlyData,
          messages: messages
        )
        selectedExternalClientCredential = nil
        capabilitySequencer.complete(token)
        return .output(output)
      } catch let error as TLS13HandshakeEngineError {
        selectedExternalClientCredential = nil
        phase = .failed
        throw error
      } catch let error as X509CertificateError {
        selectedExternalClientCredential = nil
        phase = .failed
        throw .certificate(error)
      } catch {
        selectedExternalClientCredential = nil
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .peerTrustAccepted, .peerTrustRejected, .credentialSelected,
      .credentialUnavailable:
      throw .capability(.wrongState)
    }
  }

  private mutating func resumePostHandshakeCredentialSelection(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let expectedToken = pendingPostHandshakeCapabilityToken,
      let request = postHandshakeRequest,
      var authenticationTranscript = postHandshakeTranscript.take()
    else {
      throw .capability(.wrongState)
    }
    switch response {
    case .credentialUnavailable(let token):
      do {
        let certificate = try makeEmptyClientCertificate(
          requestContext: request.requestContext.span
        )
        try authenticationTranscript.append(certificate.span)
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        capabilitySequencer.complete(token)
        return .output(
          try finalizePostHandshakeClientAuthentication(
            messages: [certificate],
            transcript: consume authenticationTranscript
          )
        )
      } catch {
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .credentialSelected(let token, let credential):
      do {
        try validateExternalClientCredential(
          credential,
          offeredSignatureSchemes: request.signatureSchemes,
          offeredDelegatedCredentialAlgorithms:
            request.delegatedCredentialAlgorithms
        )
        let uncompressed = try makeExternalCredentialCertificateMessage(
          credential,
          requestContext: request.requestContext.span
        )
        let certificate = try compressCertificateMessageIfUseful(
          uncompressed,
          peerAlgorithms: request.certificateCompressionAlgorithms
        )
        try authenticationTranscript.append(certificate.span)
        let certificateHash = try authenticationTranscript.digest(
          for: cipherSuite
        )
        let signed = TLS13HandshakeWire.certificateVerifyInput(
          role: .client,
          transcriptHash: certificateHash.span
        )
        let signatureToken = try capabilitySequencer.issue(kind: .signature)
        postHandshakeTranscript = consume authenticationTranscript
        postHandshakeCredential = credential
        postHandshakeFlightPrefix = [certificate]
        postHandshakeSignedMessage = signed
        pendingPostHandshakeCapabilityToken = signatureToken
        capabilitySequencer.complete(token)
        phase = .suspendedForPostHandshakeSignature
        return .suspended(
          .signature(
            TLS13SignatureRequest(
              token: signatureToken,
              role: .client,
              credentialIdentifier: credential.identifier,
              signatureScheme: credential.signatureScheme,
              message: signed
            )
          )
        )
      } catch let error as TLS13HandshakeEngineError {
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        phase = .failed
        throw error
      } catch let error as TLS13CapabilityError {
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        phase = .failed
        throw .capability(error)
      } catch {
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .peerTrustAccepted, .peerTrustRejected, .signature,
      .signatureRejected:
      postHandshakeTranscript = consume authenticationTranscript
      pendingPostHandshakeCapabilityToken = expectedToken
      throw .capability(.wrongState)
    }
  }

  private mutating func resumePostHandshakeSignature(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let expectedToken = pendingPostHandshakeCapabilityToken,
      let credential = postHandshakeCredential,
      let signedMessage = postHandshakeSignedMessage,
      var authenticationTranscript = postHandshakeTranscript.take()
    else {
      throw .capability(.wrongState)
    }
    switch response {
    case .signatureRejected(let token):
      pendingPostHandshakeCapabilityToken = nil
      postHandshakeRequest = nil
      postHandshakeCredential = nil
      postHandshakeSignedMessage = nil
      postHandshakeFlightPrefix = []
      capabilitySequencer.complete(token)
      phase = .failed
      throw .capability(.signatureRejected(.client))

    case .signature(let token, let signature):
      do {
        let publicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: subjectPublicKeyInfo(for: credential)
        )
        let certificateVerifyValue = TLS13CertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature
        )
        guard try publicKey.verify(
          certificateVerifyValue,
          signedMessage: signedMessage.span
        ) else {
          throw TLS13HandshakeEngineError.certificateVerifyFailure
        }
        let certificateVerify = try TLS13HandshakeCodec.makeCertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature.span
        )
        try authenticationTranscript.append(certificateVerify.span)
        var messages = postHandshakeFlightPrefix
        messages.append(certificateVerify)
        pendingPostHandshakeCapabilityToken = nil
        postHandshakeRequest = nil
        postHandshakeCredential = nil
        postHandshakeSignedMessage = nil
        postHandshakeFlightPrefix = []
        capabilitySequencer.complete(token)
        return .output(
          try finalizePostHandshakeClientAuthentication(
            messages: messages,
            transcript: consume authenticationTranscript
          )
        )
      } catch let error as TLS13HandshakeEngineError {
        phase = .failed
        throw error
      } catch {
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .peerTrustAccepted, .peerTrustRejected, .credentialSelected,
      .credentialUnavailable:
      postHandshakeTranscript = consume authenticationTranscript
      pendingPostHandshakeCapabilityToken = expectedToken
      throw .capability(.wrongState)
    }
  }

  private mutating func finalizePostHandshakeClientAuthentication(
    messages: consuming ContiguousArray<OwnedBytes>,
    transcript authenticationTranscript: consuming TLS13Transcript
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard applicationSecrets != nil else { throw .invalidState }
    var authenticationTranscript = consume authenticationTranscript
    var messages = consume messages
    let finishedHash: OwnedBytes
    do {
      finishedHash = try authenticationTranscript.digest(for: cipherSuite)
    } catch let error {
      throw .handshake(error)
    }
    let verifyData: OwnedBytes
    do {
      verifyData = try applicationSecrets!.makeClientFinishedVerifyData(
        transcriptHash: finishedHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let finished: OwnedBytes
    do {
      finished = try TLS13HandshakeCodec.makeFinished(
        verifyData: verifyData.span
      )
    } catch let error {
      throw .handshake(error)
    }
    do {
      try authenticationTranscript.append(finished.span)
    } catch let error {
      throw .handshake(error)
    }
    messages.append(finished)

    var byteCount = 0
    for message in messages {
      let addition = byteCount.addingReportingOverflow(message.count)
      guard !addition.overflow else { throw .malformedInput }
      byteCount = addition.partialValue
    }
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(byteCount)
    for message in messages {
      var index = 0
      while index < message.count {
        encoded.append(message[index])
        index += 1
      }
    }
    let bytes = OwnedBytes(consuming: encoded)
    let range: ByteRange
    do {
      range = try ByteRange(offset: 0, count: bytes.count)
    } catch let error {
      throw .output(error)
    }
    postHandshakeTranscript = nil
    postHandshakeRequest = nil
    postHandshakeCredential = nil
    postHandshakeFlightPrefix = []
    postHandshakeSignedMessage = nil
    pendingPostHandshakeCapabilityToken = nil
    phase = .established
    return try makeOutput(
      bytes: bytes,
      actions: [.emitHandshakeBytes(epoch: .application, bytes: range)]
    )
  }

  private func validateExternalClientCredential(
    _ credential: TLS13CredentialDescriptor,
    offeredSignatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    offeredDelegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >
  ) throws(TLS13HandshakeEngineError) {
    guard credential.certificateType == negotiatedClientCertificateType
    else {
      throw .capability(.invalidCredential)
    }
    switch credential.certificateType {
    case .x509:
      guard !credential.certificateEntries.isEmpty,
        credential.certificateEntries.count
          <= TLS13CertificateMessage.maximumCertificateCount
      else {
        throw .capability(.invalidCredential)
      }
      let leafBytes = credential.certificateEntries[0].certificate
      let leaf: X509Certificate
      do {
        leaf = try X509Certificate(der: leafBytes.span)
      } catch let error {
        throw .certificate(error)
      }
      let activeSubjectPublicKeyInfo = try
        TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
          for: credential.certificateEntries,
          role: .client,
          signatureSchemes: offeredSignatureSchemes,
          delegatedCredentialAlgorithms:
            offeredDelegatedCredentialAlgorithms,
          at: verificationInstant
        )
      guard leaf.validity.contains(verificationInstant),
        credential.signatureScheme.matches(activeSubjectPublicKeyInfo)
      else {
        throw .capability(.invalidCredential)
      }
      if let delegatedCredential =
        credential.certificateEntries[0].delegatedCredential
      {
        guard credential.signatureScheme
          == delegatedCredential.certificateVerifyAlgorithm
        else {
          throw .capability(.invalidCredential)
        }
      } else {
        guard offeredSignatureSchemes.contains(credential.signatureScheme) else {
          throw .capability(.invalidCredential)
        }
      }
    case .rawPublicKey:
      guard offeredSignatureSchemes.contains(credential.signatureScheme),
        credential.certificateEntries.isEmpty,
        credential.rawPublicKey != nil
      else {
        throw .capability(.invalidCredential)
      }
      _ = try subjectPublicKeyInfo(for: credential)
    }
  }

  private func certificateRequest(
    _ request: TLS13CertificateRequest,
    supports identity: borrowing TLS13ClientIdentity
  ) -> Bool {
    if let delegatedCredential = identity.delegatedCredential {
      return request.delegatedCredentialAlgorithms.contains(
        identity.signatureScheme
      ) && request.signatureSchemes.contains(
        delegatedCredential.delegationAlgorithm
      )
    }
    return request.signatureSchemes.contains(identity.signatureScheme)
  }

  private func subjectPublicKeyInfo(
    for credential: TLS13CredentialDescriptor
  ) throws(TLS13HandshakeEngineError) -> SubjectPublicKeyInfo {
    switch credential.certificateType {
    case .x509:
      guard let entry = credential.certificateEntries.first else {
        throw .capability(.invalidCredential)
      }
      if let delegatedCredential = entry.delegatedCredential {
        return delegatedCredential.subjectPublicKeyInfo
      }
      do {
        return try X509Certificate(der: entry.certificate.span)
          .subjectPublicKeyInfo
      } catch let error {
        throw .certificate(error)
      }
    case .rawPublicKey:
      guard let rawPublicKey = credential.rawPublicKey else {
        throw .capability(.invalidCredential)
      }
      do {
        return try SubjectPublicKeyInfo(der: rawPublicKey.span)
      } catch {
        throw .capability(.invalidCredential)
      }
    }
  }

  private func parsePeerCertificateMessage(
    _ encodedMessage: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13CertificateMessage {
    try TLS13CertificateCompressionProcessor.decode(
      encodedMessage,
      certificateType: negotiatedServerCertificateType,
      configuration: certificateCompression
    )
  }

  private func compressCertificateMessageIfUseful(
    _ uncompressed: OwnedBytes,
    peerAlgorithms: borrowing ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    >
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    try TLS13CertificateCompressionProcessor.encodeIfUseful(
      uncompressed,
      peerAlgorithms: peerAlgorithms,
      configuration: certificateCompression
    )
  }

  private func makeExternalCredentialCertificateMessage(
    _ credential: TLS13CredentialDescriptor,
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    switch credential.certificateType {
    case .x509:
      return try engineTry {
        try TLS13HandshakeCodec.makeCertificate(
          entries: credential.certificateEntries,
          requestContext: requestContext
        )
      }
    case .rawPublicKey:
      guard let rawPublicKey = credential.rawPublicKey else {
        throw .capability(.invalidCredential)
      }
      let entry = try engineTry {
        try TLS13CertificateEntry(certificateDER: rawPublicKey.span)
      }
      return try engineTry {
        try TLS13HandshakeCodec.makeCertificate(
          entries: [entry],
          requestContext: requestContext
        )
      }
    }
  }

  private mutating func makeEmptyClientCertificate(
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    try engineTry {
      try TLS13HandshakeCodec.makeCertificate(
        entries: [],
        requestContext: requestContext
      )
    }
  }

  private mutating func finalizeClientFlight(
    endOfEarlyData: OwnedBytes?,
    messages clientMessages: consuming ContiguousArray<OwnedBytes>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard handshakeSecrets != nil, applicationSecrets != nil else {
      throw .invalidState
    }
    var clientFlightMessages = clientMessages
    let clientFinishedHash = try transcriptDigest()
    let clientFinishedData: OwnedBytes
    do {
      clientFinishedData = try handshakeSecrets!.makeClientFinishedVerifyData(
        transcriptHash: clientFinishedHash.span
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
    try appendTranscript(clientFinished.span)
    clientFlightMessages.append(clientFinished)
    let completedHash = try transcriptDigest()
    let resumption: TLS13ResumptionMasterSecret
    do {
      resumption = try handshakeSecrets!.makeResumptionMasterSecret(
        transcriptHash: completedHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let exported: TLS13TrafficSecretPair
    do {
      exported = try applicationSecrets!.exportTrafficSecrets()
    } catch {
      throw .malformedInput
    }
    _ = handshakeSecrets.take()
    resumptionMasterSecret = consume resumption
    phase = .established
    // The final owner is materialized once because Stream, DTLS, and QUIC
    // consume one ordered handshake-byte range. Each message is appended
    // directly without converting through Array, Data, or String.
    var clientFlight = ContiguousArray<UInt8>()
    var clientFlightByteCount = endOfEarlyData?.count ?? 0
    for flightMessage in clientFlightMessages {
      clientFlightByteCount += flightMessage.count
    }
    clientFlight.reserveCapacity(clientFlightByteCount)
    if let endOfEarlyData {
      var index = 0
      while index < endOfEarlyData.count {
        clientFlight.append(endOfEarlyData[index])
        index += 1
      }
    }
    for flightMessage in clientFlightMessages {
      var index = 0
      while index < flightMessage.count {
        clientFlight.append(flightMessage[index])
        index += 1
      }
    }
    let ownedClientFlight = OwnedBytes(consuming: clientFlight)
    let handshakeRange: ByteRange
    do {
      handshakeRange = try ByteRange(
        offset: endOfEarlyData?.count ?? 0,
        count: ownedClientFlight.count - (endOfEarlyData?.count ?? 0)
      )
    } catch let error {
      throw .output(error)
    }
    var actions = ContiguousArray<TLS13HandshakeCoreAction>()
    if let endOfEarlyData {
      let earlyRange: ByteRange
      do {
        earlyRange = try ByteRange(offset: 0, count: endOfEarlyData.count)
      } catch let error {
        throw .output(error)
      }
      actions.append(.emitHandshakeBytes(epoch: .earlyData, bytes: earlyRange))
    }
    actions.append(.emitHandshakeBytes(epoch: .handshake, bytes: handshakeRange))
    actions.append(.installTrafficSecrets(epoch: .application))
    actions.append(.handshakeComplete)
    return try makeOutput(
      bytes: ownedClientFlight,
      actions: actions,
      applicationSecrets: exported
    )
  }

  private func verifyCertificateVerify(
    _ value: TLS13CertificateVerify,
    signedMessage: Span<UInt8>,
    publicKey: TLS13CertificateVerificationKey
  ) throws(TLS13HandshakeEngineError) -> Bool {
    do {
      return try publicKey.verify(value, signedMessage: signedMessage)
    } catch {
      throw .certificateVerifyFailure
    }
  }

  package mutating func exportDTLSSRTPKeyingMaterial()
    throws(TLS13HandshakeEngineError) -> DTLSSRTPKeyingMaterial
  {
    guard case .established = phase,
      let profile = negotiatedSRTPProtectionProfile,
      let masterKeyIdentifier = negotiatedSRTPMasterKeyIdentifier,
      let secrets = applicationSecrets.take()
    else {
      throw .srtp(.negotiationNotEstablished)
    }
    do {
      let keyingMaterial = try secrets.exportKeyingMaterial(
        label: "EXTRACTOR-dtls_srtp",
        context: Span<UInt8>(),
        outputByteCount: profile.exporterByteCount
      )
      applicationSecrets = consume secrets
      return DTLSSRTPKeyingMaterial(
        protectionProfile: profile,
        masterKeyIdentifier: masterKeyIdentifier,
        secret: consume keyingMaterial
      )
    } catch let error {
      applicationSecrets = consume secrets
      throw .srtp(.keySchedule(error))
    }
  }

  private borrowing func makeDTLSSRTPOffer() -> DTLSSRTPUseSRTPData? {
    srtpConfiguration.map {
      DTLSSRTPUseSRTPData(
        protectionProfiles: $0.protectionProfiles,
        masterKeyIdentifier: $0.masterKeyIdentifier
      )
    }
  }

  private mutating func validateDTLSSRTP(
    selection: DTLSSRTPUseSRTPData?
  ) throws(TLS13HandshakeEngineError) {
    switch (srtpConfiguration, selection) {
    case (.none, .none):
      return
    case (.none, .some):
      throw .srtp(.unexpectedExtension)
    case (.some, .none):
      throw .srtp(.missingExtension)
    case (.some(let configuration), .some(let selection)):
      guard selection.protectionProfileIDs.count == 1,
        let profile = DTLSSRTPProtectionProfile(
          rawValue: selection.protectionProfileIDs[0]
        )
      else {
        throw .srtp(.invalidServerSelection)
      }
      guard configuration.protectionProfiles.contains(profile) else {
        throw .srtp(.selectedProtectionProfileWasNotOffered(profile))
      }
      let identifierMatches = ConstantTime.equal(
        configuration.masterKeyIdentifier.span,
        selection.masterKeyIdentifier.span
      )
      guard selection.masterKeyIdentifier.isEmpty || identifierMatches else {
        throw .srtp(.mismatchedMasterKeyIdentifier)
      }
      guard !configuration.requiresMasterKeyIdentifierEcho || identifierMatches else {
        throw .srtp(.mismatchedMasterKeyIdentifier)
      }
      negotiatedSRTPProtectionProfile = profile
      negotiatedSRTPMasterKeyIdentifier = selection.masterKeyIdentifier
    }
  }

  private func activeServerPublicKey()
    throws(TLS13HandshakeEngineError) -> TLS13CertificateVerificationKey
  {
    guard let publicKey = validatedServerPublicKey else {
      throw .invalidState
    }
    return publicKey
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
    earlyTrafficSecret: consuming TLS13EarlyTrafficSecret? = nil,
    handshakeSecrets: consuming TLS13TrafficSecretPair? = nil,
    applicationSecrets: consuming TLS13TrafficSecretPair? = nil
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    do {
      return try TLS13HandshakeCoreOutput(
        bytes: bytes,
        actions: actions,
        earlyTrafficSecret: earlyTrafficSecret,
        handshakeSecrets: handshakeSecrets,
        applicationSecrets: applicationSecrets
      )
    } catch let error {
      switch error {
      case .byteRange(let byteError): throw .output(byteError)
      case .duplicateTrafficSecrets, .missingTrafficSecrets,
        .unreferencedTrafficSecrets, .duplicateEarlyTrafficSecret,
        .missingEarlyTrafficSecret, .unreferencedEarlyTrafficSecret:
        throw .invalidState
      }
    }
  }
}

private struct PendingServerTrust: Sendable {
  let token: TLS13CapabilityToken
  let encodedMessage: OwnedBytes
  let certificateMessage: TLS13CertificateMessage
}

private struct PendingClientCredentialSelection: Sendable {
  let token: TLS13CapabilityToken
  let signatureSchemes: ContiguousArray<TLS13SignatureScheme>
  let delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme>
  let requestContext: OwnedBytes
}

private struct PendingClientSignature: Sendable {
  let token: TLS13CapabilityToken
  let flightPrefix: ContiguousArray<OwnedBytes>
  let signedMessage: OwnedBytes
}

private func containsClientIdentity(
  _ identity: borrowing TLS13ClientIdentity?
) -> Bool {
  switch identity {
  case .some: true
  case .none: false
  }
}

private func makeResumptionBinder(
  preSharedKey: borrowing SecretBytes,
  cipherSuite: TLSCipherSuite,
  zeroClientHello: Span<UInt8>,
  echMaximumNameLength: UInt8?,
  handshakeEncoding: TLS13HandshakeEncoding
) throws -> TLS13PSKBinder {
  if let maximumNameLength = echMaximumNameLength {
    let inner = try ECHClientHelloCodec.makeInner(
      from: zeroClientHello,
      maximumNameLength: maximumNameLength,
      encoding: handshakeEncoding
    ).clientHello
    let truncated = try TLS13HandshakeCodec.truncatedClientHelloForBinder(
      inner.span,
      encoding: handshakeEncoding
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
    zeroClientHello,
    encoding: handshakeEncoding
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
import TLSTypes
