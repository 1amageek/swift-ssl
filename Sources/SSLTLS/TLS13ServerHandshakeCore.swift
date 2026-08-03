import SSLCore
import SSLCrypto
import SSLX509

/// Record-independent TLS 1.3 server state machine.
///
/// The core owns authentication, transcript, and key-schedule semantics. A
/// transport adapter owns message framing, reliability, and encryption.
public struct TLS13ServerHandshakeCore:
  TLS13ServerHandshakeCoreProtocol,
  TLS13ApplicationTrafficSecretManaging,
  ~Copyable,
  Sendable
{
  private enum Phase: Sendable {
    case awaitingClientHello
    case awaitingHelloRetryRequestCookie
    case awaitingSecondClientHello
    case awaitingEndOfEarlyData
    case awaitingClientFinished
    case suspendedForPeerTrust
    case suspendedForCredentialSelection
    case suspendedForSignature
    case suspendedForPostHandshakePeerTrust
    case established
    case failed
  }

  private let random: OwnedBytes
  private var keyExchange: TLS13ServerKeyExchangeState
  private let keyExchangeEntropy: any EntropySource
  private let serverCredential: TLS13ServerCredentialStorage
  private let usesExternalServerCredential: Bool
  private let supportedServerCertificateTypes:
    ContiguousArray<TLS13CertificateType>
  private var externalServerCredential: TLS13CredentialDescriptor?
  private let verificationInstant: VerificationInstant
  private let applicationProtocolSelector:
    (any TLS13ApplicationProtocolSelecting)?
  private let clientAuthentication: TLS13ClientAuthenticationConfiguration?
  private let localTransportParameters: OwnedBytes?
  private let resumptionIdentity: OwnedBytes?
  private let resumptionPSK: SecretBytes?
  private let resumptionIssuedAt: VerificationInstant?
  private let resumptionLifetime: UInt32?
  private let resumptionAgeAdd: UInt32?
  private let resumptionAgeToleranceMilliseconds: UInt32
  private let resumptionMaximumEarlyDataByteCount: UInt32
  private let resumptionApplicationProtocol: TLS13ApplicationProtocol?
  private let earlyDataConfiguration: TLS13EarlyDataServerConfiguration?
  private var echOpener: RFC9849ECHClientHelloOpener?
  private let echRetryConfigurations: ECHConfigList?
  private var cipherSuite: TLSCipherSuite
  private let handshakeEncoding: TLS13HandshakeEncoding
  private var localConnectionID: OwnedBytes?
  private var expectedPeerConnectionID: OwnedBytes?
  private var srtpConfiguration: DTLSSRTPServerConfiguration?
  private var negotiatedSRTPProtectionProfile: DTLSSRTPProtectionProfile?
  private var negotiatedSRTPMasterKeyIdentifier: OwnedBytes?
  private var transcript: TLS13Transcript
  private var echAccepted: Bool
  private var echRejected: Bool
  private var firstAuthenticatedClientHello: OwnedBytes?
  private var retryCookie: OwnedBytes?
  private var resumedHandshake: Bool
  private var earlyDataStateStorage: TLS13EarlyDataState
  private var earlyDataByteLimitStorage: UInt32
  private var shouldDeriveEarlyTrafficSecret: Bool
  private var handshakeSecrets: TLS13HandshakeSecrets?
  private var applicationSecrets: TLS13ApplicationSecrets?
  private var resumptionMasterSecret: TLS13ResumptionMasterSecret?
  private var selectedApplicationProtocol: TLS13ApplicationProtocol?
  private var peerTransportParameters: OwnedBytes?
  private var validatedClientCertificate: TLS13ValidatedClientCertificate?
  private var validatedClientPublicKey: TLS13CertificateVerificationKey?
  private var negotiatedServerCertificateType: TLS13CertificateType
  private var negotiatedClientCertificateType: TLS13CertificateType
  private var selectedServerCertificateTypeExtension: TLS13CertificateType?
  private var selectedClientCertificateTypeExtension: TLS13CertificateType?
  private var certificateCompression:
    TLS13CertificateCompressionConfiguration?
  private var peerCertificateCompressionAlgorithms:
    ContiguousArray<TLS13CertificateCompressionAlgorithm>
  private var peerDelegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme>
  private var sawClientCertificate: Bool
  private var sawClientCertificateVerify: Bool
  private var capabilitySequencer: TLS13CapabilitySequencer
  private var pendingClientTrust: PendingClientTrust?
  private var pendingServerCredentialSelection: PendingServerCredentialSelection?
  private var pendingServerSignature: PendingServerSignature?
  private var pendingServerEarlyTrafficSecret: TLS13EarlyTrafficSecret?
  private var pendingServerHandshakeSecrets: TLS13TrafficSecretPair?
  private var peerOfferedPostHandshakeAuthentication: Bool
  private var usedPostHandshakeAuthenticationContexts: Set<OwnedBytes>
  private var postHandshakeTranscript: TLS13Transcript?
  private var postHandshakeRequestContext: OwnedBytes?
  private var postHandshakeValidatedClientCertificate:
    TLS13ValidatedClientCertificate?
  private var postHandshakeValidatedClientPublicKey:
    TLS13CertificateVerificationKey?
  private var postHandshakeSawClientCertificate: Bool
  private var postHandshakeSawClientCertificateVerify: Bool
  private var pendingPostHandshakeClientTrust: PendingClientTrust?
  private var phase: Phase

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(
        x25519: TLS13X25519ServerKeyExchange(privateKey: ephemeralKey)
      ),
      keyExchangeEntropy: SystemEntropySource(),
      credential: .local(
        certificateEntries: try Self.makeSingleCertificateEntry(
          certificateDER: certificateDER
        ),
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(
        x25519: TLS13X25519ServerKeyExchange(privateKey: ephemeralKey)
      ),
      keyExchangeEntropy: SystemEntropySource(),
      credential: .local(
        certificateEntries: certificateEntries,
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: try Self.makeSingleCertificateEntry(
          certificateDER: certificateDER
        ),
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: certificateEntries,
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(p256: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: try Self.makeSingleCertificateEntry(
          certificateDER: certificateDER
        ),
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(p256: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: certificateEntries,
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateDER: Span<UInt8>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519MLKEM768: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: try Self.makeSingleCertificateEntry(
          certificateDER: certificateDER
        ),
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519MLKEM768: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .local(
        certificateEntries: certificateEntries,
        signingKey: signingKey
      ),
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
      handshakeEncoding: handshakeEncoding
    )
  }

  private init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13ServerKeyExchangeState,
    keyExchangeEntropy: consuming any EntropySource,
    credential: consuming TLS13ServerCredentialStorage,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)?,
    clientAuthentication: TLS13ClientAuthenticationConfiguration?,
    transportParameters: Span<UInt8>?,
    resumptionIdentity: Span<UInt8>?,
    resumptionPSK: Span<UInt8>?,
    resumptionIssuedAt: VerificationInstant?,
    resumptionLifetime: UInt32?,
    resumptionAgeAdd: UInt32?,
    resumptionAgeToleranceMilliseconds: UInt32,
    resumptionMaximumEarlyDataByteCount: UInt32,
    resumptionApplicationProtocol: TLS13ApplicationProtocol?,
    earlyDataConfiguration: TLS13EarlyDataServerConfiguration?,
    echConfigurations: ECHServerConfigurationSet?,
    handshakeEncoding: TLS13HandshakeEncoding,
    usesExternalServerCredential: Bool = false,
    supportedServerCertificateTypes:
      ContiguousArray<TLS13CertificateType> = [.x509]
  ) throws(TLS13HandshakeEngineError) {
    guard random.count == 32 else { throw .invalidConfiguration }
    guard credential.isExternal == usesExternalServerCredential else {
      throw .invalidConfiguration
    }
    guard !supportedServerCertificateTypes.isEmpty else {
      throw .invalidConfiguration
    }
    var certificateTypeIndex = 0
    while certificateTypeIndex < supportedServerCertificateTypes.count {
      var priorIndex = 0
      while priorIndex < certificateTypeIndex {
        guard
          supportedServerCertificateTypes[priorIndex]
            != supportedServerCertificateTypes[certificateTypeIndex]
        else {
          throw .invalidConfiguration
        }
        priorIndex += 1
      }
      certificateTypeIndex += 1
    }
    if !usesExternalServerCredential {
      guard supportedServerCertificateTypes == [.x509] else {
        throw .invalidConfiguration
      }
    }
    let parsed = try credential.validatedLeaf(at: verificationInstant)
    guard (resumptionIdentity == nil) == (resumptionPSK == nil) else {
      throw .invalidConfiguration
    }
    let hasAgeMetadata =
      resumptionIssuedAt != nil
      && resumptionLifetime != nil
      && resumptionAgeAdd != nil
    guard (resumptionIdentity == nil) == !hasAgeMetadata else {
      throw .invalidConfiguration
    }
    if let lifetime = resumptionLifetime {
      guard lifetime > 0 else { throw .invalidConfiguration }
    }
    guard resumptionAgeToleranceMilliseconds <= 60_000 else {
      throw .invalidConfiguration
    }
    guard earlyDataConfiguration == nil || handshakeEncoding != .dtls13 else {
      throw .invalidConfiguration
    }
    guard resumptionMaximumEarlyDataByteCount == 0 || resumptionIdentity != nil else {
      throw .invalidConfiguration
    }
    let configuredIdentity: OwnedBytes?
    let configuredPSK: SecretBytes?
    if let identity = resumptionIdentity, let psk = resumptionPSK {
      guard !identity.isEmpty, psk.count <= 64 else { throw .invalidConfiguration }
      configuredIdentity = OwnedBytes(copying: identity)
      do {
        configuredPSK = try SecretBytes(copying: psk)
      } catch {
        throw .invalidConfiguration
      }
    } else {
      configuredIdentity = nil
      configuredPSK = nil
    }
    if let echConfigurations, let parsed {
      for configuration in echConfigurations.configurations {
        do {
          try parsed.verifyDNSName(configuration.config.publicName.span)
        } catch {
          throw .certificateVerificationFailed
        }
      }
    }
    do {
      transcript = try TLS13Transcript()
    } catch let error {
      throw .handshake(error)
    }
    self.random = OwnedBytes(copying: random)
    self.keyExchange = consume keyExchange
    self.keyExchangeEntropy = keyExchangeEntropy
    serverCredential = consume credential
    self.usesExternalServerCredential = usesExternalServerCredential
    self.supportedServerCertificateTypes = supportedServerCertificateTypes
    externalServerCredential = nil
    self.verificationInstant = verificationInstant
    self.applicationProtocolSelector = applicationProtocolSelector
    self.clientAuthentication = clientAuthentication
    if let transportParameters {
      localTransportParameters = OwnedBytes(copying: transportParameters)
    } else {
      localTransportParameters = nil
    }
    self.resumptionIdentity = configuredIdentity
    self.resumptionPSK = configuredPSK
    self.resumptionIssuedAt = resumptionIssuedAt
    self.resumptionLifetime = resumptionLifetime
    self.resumptionAgeAdd = resumptionAgeAdd
    self.resumptionAgeToleranceMilliseconds = resumptionAgeToleranceMilliseconds
    self.resumptionMaximumEarlyDataByteCount = resumptionMaximumEarlyDataByteCount
    self.resumptionApplicationProtocol = resumptionApplicationProtocol
    self.earlyDataConfiguration = earlyDataConfiguration
    echRetryConfigurations = echConfigurations?.retryConfigurations
    echOpener = nil
    cipherSuite = .aes128GCM_SHA256
    self.handshakeEncoding = handshakeEncoding
    localConnectionID = nil
    expectedPeerConnectionID = nil
    srtpConfiguration = nil
    negotiatedSRTPProtectionProfile = nil
    negotiatedSRTPMasterKeyIdentifier = nil
    echAccepted = false
    echRejected = false
    firstAuthenticatedClientHello = nil
    retryCookie = nil
    resumedHandshake = false
    earlyDataStateStorage = .notRequested
    earlyDataByteLimitStorage = 0
    shouldDeriveEarlyTrafficSecret = false
    handshakeSecrets = nil
    applicationSecrets = nil
    resumptionMasterSecret = nil
    selectedApplicationProtocol = nil
    peerTransportParameters = nil
    validatedClientCertificate = nil
    validatedClientPublicKey = nil
    negotiatedServerCertificateType = .x509
    negotiatedClientCertificateType = clientAuthentication?.certificateType ?? .x509
    selectedServerCertificateTypeExtension = nil
    selectedClientCertificateTypeExtension = nil
    certificateCompression = nil
    peerCertificateCompressionAlgorithms = []
    peerDelegatedCredentialAlgorithms = []
    sawClientCertificate = false
    sawClientCertificateVerify = false
    capabilitySequencer = TLS13CapabilitySequencer(
      random: random,
      role: .server
    )
    pendingClientTrust = nil
    pendingServerCredentialSelection = nil
    pendingServerSignature = nil
    pendingServerEarlyTrafficSecret = nil
    pendingServerHandshakeSecrets = nil
    peerOfferedPostHandshakeAuthentication = false
    usedPostHandshakeAuthenticationContexts = []
    postHandshakeTranscript = nil
    postHandshakeRequestContext = nil
    postHandshakeValidatedClientCertificate = nil
    postHandshakeValidatedClientPublicKey = nil
    postHandshakeSawClientCertificate = false
    postHandshakeSawClientCertificateVerify = false
    pendingPostHandshakeClientTrust = nil
    phase = .awaitingClientHello
    if let echConfigurations {
      echOpener = RFC9849ECHClientHelloOpener(
        configurations: echConfigurations
      )
    }
  }

  public init(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(
        x25519: TLS13X25519ServerKeyExchange(privateKey: ephemeralKey)
      ),
      keyExchangeEntropy: SystemEntropySource(),
      credential: .external,
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
      handshakeEncoding: handshakeEncoding,
      usesExternalServerCredential: true,
      supportedServerCertificateTypes: externalServerCredential.certificateTypes
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .external,
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
      handshakeEncoding: handshakeEncoding,
      usesExternalServerCredential: true,
      supportedServerCertificateTypes: externalServerCredential.certificateTypes
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(p256: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .external,
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
      handshakeEncoding: handshakeEncoding,
      usesExternalServerCredential: true,
      supportedServerCertificateTypes: externalServerCredential.certificateTypes
    )
  }

  public init(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    transportParameters: Span<UInt8>? = nil,
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
    handshakeEncoding: TLS13HandshakeEncoding = .tls13
  ) throws(TLS13HandshakeEngineError) {
    try self.init(
      random: random,
      keyExchange: TLS13ServerKeyExchangeState(x25519MLKEM768: keyExchange),
      keyExchangeEntropy: keyExchangeEntropy,
      credential: .external,
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
      handshakeEncoding: handshakeEncoding,
      usesExternalServerCredential: true,
      supportedServerCertificateTypes: externalServerCredential.certificateTypes
    )
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

  public var srtpProtectionProfile: DTLSSRTPProtectionProfile? {
    guard isEstablished else { return nil }
    return negotiatedSRTPProtectionProfile
  }

  public var srtpMasterKeyIdentifier: OwnedBytes? {
    guard isEstablished else { return nil }
    return negotiatedSRTPMasterKeyIdentifier
  }

  public var authenticatedClientIdentity: TLS13ValidatedClientCertificate? {
    guard case .established = phase, sawClientCertificateVerify else {
      return nil
    }
    return validatedClientCertificate
  }

  /// Configures the algorithms this endpoint can use to decompress peer
  /// certificates and to compress its own certificate when requested.
  public mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(TLS13HandshakeEngineError) {
    guard case .awaitingClientHello = phase else { throw .invalidState }
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
    clientAuthentication?.certificateType == .x509
      ? [.ecdsaP256SHA256, .ed25519] : []
  }

  private var mainHandshakeClientAuthentication:
    TLS13ClientAuthenticationConfiguration?
  {
    guard let clientAuthentication,
      clientAuthentication.timing.includesMainHandshake
    else {
      return nil
    }
    return clientAuthentication
  }

  package var isAwaitingInitialClientHello: Bool {
    if case .awaitingClientHello = phase { return true }
    return false
  }

  package var isAwaitingSecondClientHello: Bool {
    if case .awaitingSecondClientHello = phase { return true }
    return false
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
    guard case .awaitingClientHello = phase else { throw .invalidState }
    localConnectionID = local
    expectedPeerConnectionID = expectedPeer
  }

  package mutating func configureDTLSSRTP(
    _ configuration: DTLSSRTPServerConfiguration
  ) throws(TLS13HandshakeEngineError) {
    guard handshakeEncoding == .dtls13 else {
      throw .invalidConfiguration
    }
    guard case .awaitingClientHello = phase else { throw .invalidState }
    srtpConfiguration = configuration
  }

  /// Starts one RFC 8446 post-handshake client-authentication exchange.
  public mutating func requestPostHandshakeClientAuthentication(
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard case .established = phase,
      let clientAuthentication,
      clientAuthentication.timing.includesPostHandshake,
      peerOfferedPostHandshakeAuthentication,
      applicationSecrets != nil,
      !requestContext.isEmpty,
      requestContext.count <= UInt8.max,
      postHandshakeTranscript == nil,
      pendingPostHandshakeClientTrust == nil
    else {
      throw .invalidState
    }
    let context = OwnedBytes(copying: requestContext)
    guard !usedPostHandshakeAuthenticationContexts.contains(context) else {
      throw .invalidConfiguration
    }
    do {
      let request = try TLS13HandshakeCodec.makeCertificateRequest(
        requestContext: requestContext,
        signatureSchemes: [
          .ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519,
        ],
        certificateCompressionAlgorithms:
          advertisedCertificateCompressionAlgorithms,
        delegatedCredentialAlgorithms:
          advertisedDelegatedCredentialAlgorithms
      )
      var authenticationTranscript = transcript.clone()
      try authenticationTranscript.append(request.span)
      usedPostHandshakeAuthenticationContexts.insert(context)
      postHandshakeTranscript = consume authenticationTranscript
      postHandshakeRequestContext = context
      postHandshakeValidatedClientCertificate = nil
      postHandshakeValidatedClientPublicKey = nil
      postHandshakeSawClientCertificate = false
      postHandshakeSawClientCertificateVerify = false
      return try makeEmission(request, at: .application)
    } catch let error as TLS13HandshakeEngineError {
      throw error
    } catch let error as TLS13HandshakeError {
      throw .handshake(error)
    } catch {
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func receiveHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    if usesExternalServerCredential,
      externalServerCredential == nil,
      epoch == .initial,
      case .awaitingClientHello = phase
    {
      throw .capability(.wrongState)
    }
    if usesExternalServerCredential,
      externalServerCredential == nil,
      epoch == .initial,
      case .awaitingSecondClientHello = phase
    {
      throw .capability(.wrongState)
    }
    if mainHandshakeClientAuthentication != nil,
      mainHandshakeClientAuthentication?.validator == nil,
      case .awaitingClientFinished = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateType
        || message[0] == TLS13HandshakeCodec.compressedCertificateType
    {
      let certificateMessage: TLS13CertificateMessage
      do {
        certificateMessage = try parsePeerCertificateMessage(message)
      } catch let error {
        phase = .failed
        throw error
      }
      if !certificateMessage.entries.isEmpty {
        throw .capability(.wrongState)
      }
    }
    do {
      switch phase {
      case .awaitingClientHello:
        guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveClientHello(message)
      case .awaitingSecondClientHello:
        guard epoch == .initial else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveSecondClientHello(message)
      case .awaitingClientFinished:
        guard epoch == .handshake else { throw TLS13HandshakeEngineError.malformedInput }
        return try receiveClientFlightMessage(message)
      case .established:
        guard epoch == .application, postHandshakeTranscript != nil else {
          throw TLS13HandshakeEngineError.invalidState
        }
        return try receivePostHandshakeClientAuthenticationMessage(message)
      case .awaitingEndOfEarlyData:
        guard epoch == .earlyData else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        try engineTry { try TLS13HandshakeCodec.parseEndOfEarlyData(message) }
        try appendTranscript(message)
        phase = .awaitingClientFinished
        return try makeOutput(bytes: OwnedBytes(), actions: [])
      case .awaitingHelloRetryRequestCookie, .suspendedForPeerTrust,
        .suspendedForCredentialSelection, .suspendedForSignature,
        .suspendedForPostHandshakePeerTrust, .failed:
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
      postHandshakeTranscript != nil,
      !message.isEmpty,
      (message[0] == TLS13HandshakeCodec.certificateType
        || message[0] == TLS13HandshakeCodec.compressedCertificateType)
    {
      do {
        let certificateMessage = try parsePeerCertificateMessage(message)
        if !certificateMessage.entries.isEmpty,
          clientAuthentication?.validator == nil
        {
          return .suspended(
            try suspendForPostHandshakeClientTrust(
              encodedMessage: message,
              certificateMessage: certificateMessage
            )
          )
        }
      } catch let error {
        phase = .failed
        throw error
      }
    }
    if usesExternalServerCredential,
      externalServerCredential == nil,
      epoch == .initial
    {
      do {
        let processed: ECHProcessedClientHello
        let includesRetry: Bool
        switch phase {
        case .awaitingClientHello:
          processed = try processClientHello(message)
          includesRetry = false
        case .awaitingSecondClientHello:
          processed = try prepareRetriedClientHello(message)
          includesRetry = true
        default:
          throw TLS13HandshakeEngineError.invalidState
        }
        return try suspendForServerCredentialSelection(
          processed,
          binderTranscriptIncludesRetry: includesRetry
        )
      } catch let error as TLS13HandshakeEngineError {
        phase = .failed
        throw error
      } catch {
        phase = .failed
        throw mapHandshakeEngineError(error)
      }
    }
    if mainHandshakeClientAuthentication != nil,
      mainHandshakeClientAuthentication?.validator == nil,
      case .awaitingClientFinished = phase,
      epoch == .handshake,
      !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateType
        || message[0] == TLS13HandshakeCodec.compressedCertificateType
    {
      do {
        let certificateMessage = try parsePeerCertificateMessage(message)
        if !certificateMessage.entries.isEmpty {
          return .suspended(
            try suspendForClientTrust(
              encodedMessage: message,
              certificateMessage: certificateMessage
            )
          )
        }
      } catch let error {
        phase = .failed
        throw error
      }
    }
    return .output(try receiveHandshakeMessage(message, at: epoch))
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
      return try resumePeerTrust(response)
    case .suspendedForCredentialSelection:
      return try resumeServerCredentialSelection(response)
    case .suspendedForSignature:
      return try resumeServerSignature(response)
    case .suspendedForPostHandshakePeerTrust:
      return try resumePostHandshakePeerTrust(response)
    default:
      throw .capability(.wrongState)
    }
  }

  private mutating func resumePeerTrust(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingClientTrust else {
      throw .capability(.wrongState)
    }

    switch response {
    case .peerTrustRejected(let token):
      capabilitySequencer.complete(token)
      pendingClientTrust = nil
      phase = .failed
      throw .capability(.peerTrustRejected(.client))

    case .peerTrustAccepted(let token):
      do {
        let activeSubjectPublicKeyInfo = try subjectPublicKeyInfo(
          for: pending.certificateMessage
        )
        let publicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: activeSubjectPublicKeyInfo
        )
        let leafSubjectPublicKeyInfo: SubjectPublicKeyInfo
        switch pending.certificateMessage.certificateType {
        case .x509:
          let leaf = pending.certificateMessage.entries[0].certificate
          leafSubjectPublicKeyInfo = try X509Certificate(der: leaf.span)
            .subjectPublicKeyInfo
        case .rawPublicKey:
          leafSubjectPublicKeyInfo = activeSubjectPublicKeyInfo
        }
        validatedClientCertificate = TLS13ValidatedClientCertificate(
          certificateMessage: pending.certificateMessage,
          leafSubjectPublicKeyInfo: leafSubjectPublicKeyInfo
        )
        validatedClientPublicKey = publicKey
        try appendTranscript(pending.encodedMessage.span)
        sawClientCertificate = true
        capabilitySequencer.complete(token)
        pendingClientTrust = nil
        phase = .awaitingClientFinished
        return .output(try makeOutput(bytes: OwnedBytes(), actions: []))
      } catch let error as TLS13HandshakeEngineError {
        pendingClientTrust = nil
        phase = .failed
        throw error
      } catch let error as X509CertificateError {
        pendingClientTrust = nil
        phase = .failed
        throw .certificate(error)
      } catch {
        pendingClientTrust = nil
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
      return pendingClientTrust?.token
    case .suspendedForCredentialSelection:
      return pendingServerCredentialSelection?.token
    case .suspendedForSignature:
      return pendingServerSignature?.token
    case .suspendedForPostHandshakePeerTrust:
      return pendingPostHandshakeClientTrust?.token
    default:
      return nil
    }
  }

  private mutating func suspendForClientTrust(
    encodedMessage: Span<UInt8>,
    certificateMessage: TLS13CertificateMessage
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest {
    guard case .awaitingClientFinished = phase,
      mainHandshakeClientAuthentication != nil,
      mainHandshakeClientAuthentication?.validator == nil,
      certificateMessage.requestContext.isEmpty,
      !certificateMessage.entries.isEmpty,
      !resumedHandshake,
      !sawClientCertificate,
      !sawClientCertificateVerify,
      pendingClientTrust == nil
    else {
      throw .invalidState
    }
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .peerTrustEvaluation)
    } catch let error {
      throw .capability(error)
    }
    pendingClientTrust = PendingClientTrust(
      token: token,
      encodedMessage: OwnedBytes(copying: encodedMessage),
      certificateMessage: certificateMessage
    )
    phase = .suspendedForPeerTrust
    return .peerTrustEvaluation(
      TLS13PeerTrustEvaluationRequest(
        token: token,
        peer: .client,
        certificateMessage: certificateMessage,
        serverName: nil,
        verificationInstant: verificationInstant
      )
    )
  }

  private mutating func suspendForServerCredentialSelection(
    _ processed: ECHProcessedClientHello,
    binderTranscriptIncludesRetry: Bool
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard usesExternalServerCredential,
      externalServerCredential == nil,
      pendingServerCredentialSelection == nil
    else {
      throw .invalidState
    }
    let clientHello = try engineTry {
      try TLS13HandshakeCodec.parseClientHello(
        processed.encoded.span,
        encoding: handshakeEncoding
      )
    }
    peerCertificateCompressionAlgorithms =
      clientHello.certificateCompressionAlgorithms
    peerDelegatedCredentialAlgorithms =
      clientHello.delegatedCredentialAlgorithms
    peerOfferedPostHandshakeAuthentication =
      clientHello.offersPostHandshakeAuthentication
    let resumes = try acceptResumption(
      clientHello: clientHello,
      encodedClientHello: processed.encoded.span,
      binderTranscriptIncludesRetry: binderTranscriptIncludesRetry
    )
    if resumes {
      return try receiveAuthenticatedClientHello(
        processed,
        binderTranscriptIncludesRetry: binderTranscriptIncludesRetry
      )
    }
    let availableCertificateTypes = availableServerCertificateTypes(
      for: clientHello
    )
    guard !availableCertificateTypes.isEmpty else {
      throw .certificateVerificationFailed
    }
    guard clientHello.signatureSchemes.contains(where: {
      $0 == .ecdsaP256SHA256
        || $0 == .rsaPSSRSAESHA256
        || $0 == .ed25519
    }) else {
      throw .certificateVerifyFailure
    }
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .credentialSelection)
    } catch let error {
      throw .capability(error)
    }
    pendingServerCredentialSelection = PendingServerCredentialSelection(
      token: token,
      processedClientHello: processed,
      binderTranscriptIncludesRetry: binderTranscriptIncludesRetry,
      signatureSchemes: clientHello.signatureSchemes,
      delegatedCredentialAlgorithms:
        clientHello.delegatedCredentialAlgorithms,
      certificateTypes: availableCertificateTypes
    )
    phase = .suspendedForCredentialSelection
    return .suspended(
      .credentialSelection(
        TLS13CredentialSelectionRequest(
          token: token,
          role: .server,
          serverName: clientHello.serverName,
          signatureSchemes: clientHello.signatureSchemes,
          delegatedCredentialAlgorithms:
            clientHello.delegatedCredentialAlgorithms,
          certificateTypes: availableCertificateTypes,
          certificateRequestContext: nil,
          verificationInstant: verificationInstant
        )
      )
    )
  }

  private mutating func resumeServerCredentialSelection(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingServerCredentialSelection else {
      throw .capability(.wrongState)
    }
    switch response {
    case .credentialUnavailable(let token):
      capabilitySequencer.complete(token)
      pendingServerCredentialSelection = nil
      phase = .failed
      throw .capability(.credentialUnavailable(.server))

    case .credentialSelected(let token, let credential):
      do {
        try validateExternalCredential(
          credential,
          offeredSignatureSchemes: pending.signatureSchemes,
          offeredDelegatedCredentialAlgorithms:
            pending.delegatedCredentialAlgorithms,
          offeredCertificateTypes: pending.certificateTypes
        )
        externalServerCredential = credential
        negotiatedServerCertificateType = credential.certificateType
        capabilitySequencer.complete(token)
        pendingServerCredentialSelection = nil
        phase = pending.binderTranscriptIncludesRetry
          ? .awaitingSecondClientHello
          : .awaitingClientHello
        return try receiveAuthenticatedClientHello(
          pending.processedClientHello,
          binderTranscriptIncludesRetry: pending.binderTranscriptIncludesRetry
        )
      } catch let error as TLS13HandshakeEngineError {
        pendingServerCredentialSelection = nil
        phase = .failed
        throw error
      } catch {
        pendingServerCredentialSelection = nil
        phase = .failed
        throw .capability(.invalidCredential)
      }

    case .peerTrustAccepted, .peerTrustRejected, .signature,
      .signatureRejected:
      throw .capability(.wrongState)
    }
  }

  private func validateExternalCredential(
    _ credential: TLS13CredentialDescriptor,
    offeredSignatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    offeredDelegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >,
    offeredCertificateTypes: borrowing ContiguousArray<TLS13CertificateType>
  ) throws(TLS13HandshakeEngineError) {
    guard offeredCertificateTypes.contains(credential.certificateType)
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
          role: .server,
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

  private func subjectPublicKeyInfo(
    for certificateMessage: TLS13CertificateMessage
  ) throws(TLS13HandshakeEngineError) -> SubjectPublicKeyInfo {
    try TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
      for: certificateMessage,
      role: .client,
      signatureSchemes:
        TLS13DelegatedCredentialProcessor.signatureSchemes,
      delegatedCredentialAlgorithms: advertisedDelegatedCredentialAlgorithms,
      at: verificationInstant
    )
  }

  private func parsePeerCertificateMessage(
    _ encodedMessage: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13CertificateMessage {
    try TLS13CertificateCompressionProcessor.decode(
      encodedMessage,
      certificateType: negotiatedClientCertificateType,
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
    _ credential: TLS13CredentialDescriptor
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    switch credential.certificateType {
    case .x509:
      return try engineTry {
        try TLS13HandshakeCodec.makeCertificate(
          entries: credential.certificateEntries
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
        try TLS13HandshakeCodec.makeCertificate(entries: [entry])
      }
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
    ticket: Span<UInt8>,
    ticketNonce: Span<UInt8>,
    issuedAt: VerificationInstant,
    lifetime: UInt32,
    ageAdd: UInt32,
    maximumEarlyDataByteCount: UInt32 = 0
  ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState {
    guard case .established = phase,
      let masterSecret = resumptionMasterSecret.take()
    else {
      throw .invalidState
    }
    do {
      let state = try masterSecret.withBorrowedBytes {
        master throws(TLS13ResumptionError) in
        try TLS13ResumptionState(
          ticket: ticket,
          ticketNonce: ticketNonce,
          resumptionMasterSecret: master,
          cipherSuite: masterSecret.cipherSuite,
          issuedAt: issuedAt,
          lifetime: lifetime,
          ageAdd: ageAdd,
          maximumEarlyDataByteCount: maximumEarlyDataByteCount,
          applicationProtocol: selectedApplicationProtocol
        )
      }
      resumptionMasterSecret = consume masterSecret
      return state
    } catch let error {
      resumptionMasterSecret = consume masterSecret
      throw .resumption(error)
    }
  }

  private mutating func receiveClientHello(
    _ encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let processed = try processClientHello(encodedClientHello)
    let transition = try receiveAuthenticatedClientHello(
      processed,
      binderTranscriptIncludesRetry: false
    )
    switch consume transition {
    case .output(let output): return output
    case .suspended: throw .capability(.wrongState)
    }
  }

  package mutating func prepareHelloRetryRequest(
    for encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLSCipherSuite {
    guard case .awaitingClientHello = phase else { throw .invalidState }
    do {
      let processed = try processClientHello(encodedClientHello)
      let authenticatedClientHello = processed.encoded
      let clientHello = try TLS13HandshakeCodec.parseClientHello(
        authenticatedClientHello.span,
        encoding: handshakeEncoding
      )
      guard clientHello.cookie == nil else {
        throw TLS13HandshakeEngineError.malformedInput
      }
      try validateRetryEligibleClientHello(clientHello)
      if clientHello.offersEarlyData {
        guard handshakeEncoding != .dtls13 else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        earlyDataStateStorage = .rejected
      }
      cipherSuite = clientHello.cipherSuite
      echAccepted = processed.echAccepted
      echRejected = processed.echRejected
      firstAuthenticatedClientHello = authenticatedClientHello
      try transcript.append(authenticatedClientHello.span)
      try transcript.replaceWithMessageHash(for: cipherSuite)
      phase = .awaitingHelloRetryRequestCookie
      return cipherSuite
    } catch let error as TLS13HandshakeEngineError {
      phase = .failed
      throw error
    } catch {
      phase = .failed
      throw mapHandshakeEngineError(error)
    }
  }

  package mutating func completeHelloRetryRequest(
    cookie: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard case .awaitingHelloRetryRequestCookie = phase,
      !cookie.isEmpty,
      let firstClientHello = firstAuthenticatedClientHello
    else {
      throw .invalidState
    }
    do {
      var helloRetryRequest: OwnedBytes
      if echAccepted {
        let zeroConfirmation = ContiguousArray<UInt8>(
          repeating: 0,
          count: ECHAcceptanceConfirmation.byteCount
        )
        helloRetryRequest = try TLS13HandshakeCodec.makeHelloRetryRequest(
          cookie: cookie,
          cipherSuite: cipherSuite,
          echAcceptanceConfirmation: zeroConfirmation.span,
          encoding: handshakeEncoding
        )
        let confirmation = try ECHAcceptanceConfirmation
          .computeHelloRetryRequest(
            innerClientHello: firstClientHello.span,
            helloRetryRequest: helloRetryRequest.span,
            cipherSuite: cipherSuite,
            handshakeEncoding: handshakeEncoding
          )
        helloRetryRequest = try TLS13HandshakeCodec.makeHelloRetryRequest(
          cookie: cookie,
          cipherSuite: cipherSuite,
          echAcceptanceConfirmation: confirmation.span,
          encoding: handshakeEncoding
        )
      } else {
        helloRetryRequest = try TLS13HandshakeCodec.makeHelloRetryRequest(
          cookie: cookie,
          cipherSuite: cipherSuite,
          encoding: handshakeEncoding
        )
      }
      try transcript.append(helloRetryRequest.span)
      retryCookie = OwnedBytes(copying: cookie)
      phase = .awaitingSecondClientHello
      let range = try ByteRange(offset: 0, count: helloRetryRequest.count)
      var actions: ContiguousArray<TLS13HandshakeCoreAction> = [
        .emitHandshakeBytes(epoch: .initial, bytes: range)
      ]
      if earlyDataStateStorage == .rejected {
        actions.append(.earlyDataRejected)
      }
      return try makeOutput(
        bytes: helloRetryRequest,
        actions: actions
      )
    } catch let error as TLS13HandshakeEngineError {
      phase = .failed
      throw error
    } catch {
      phase = .failed
      throw mapHandshakeEngineError(error)
    }
  }

  private mutating func receiveSecondClientHello(
    _ encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    let processed = try prepareRetriedClientHello(encodedClientHello)
    let transition = try receiveAuthenticatedClientHello(
      processed,
      binderTranscriptIncludesRetry: true
    )
    switch consume transition {
    case .output(let output): return output
    case .suspended: throw .capability(.wrongState)
    }
  }

  private mutating func prepareRetriedClientHello(
    _ encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ECHProcessedClientHello {
    guard let firstClientHello = firstAuthenticatedClientHello,
      let retryCookie
    else {
      throw .invalidState
    }
    let processed = try processRetriedClientHello(encodedClientHello)
    let matches = try engineTry {
      try TLS13HandshakeCodec.clientHellosMatchForRetry(
        firstClientHello: firstClientHello.span,
        secondClientHello: processed.encoded.span,
        cookie: retryCookie.span,
        encoding: handshakeEncoding
      )
    }
    guard matches,
      processed.echAccepted == echAccepted,
      processed.echRejected == echRejected
    else {
      throw .malformedInput
    }
    firstAuthenticatedClientHello = nil
    self.retryCookie = nil
    return processed
  }

  private mutating func receiveAuthenticatedClientHello(
    _ processed: ECHProcessedClientHello,
    binderTranscriptIncludesRetry: Bool
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    let authenticatedClientHello = processed.encoded
    echAccepted = processed.echAccepted
    echRejected = processed.echRejected
    let clientHello = try engineTry {
      try TLS13HandshakeCodec.parseClientHello(
        authenticatedClientHello.span,
        encoding: handshakeEncoding
      )
    }
    peerOfferedPostHandshakeAuthentication =
      clientHello.offersPostHandshakeAuthentication
    peerCertificateCompressionAlgorithms =
      clientHello.certificateCompressionAlgorithms
    peerDelegatedCredentialAlgorithms =
      clientHello.delegatedCredentialAlgorithms
    if let expectedPeerConnectionID {
      guard clientHello.connectionID == expectedPeerConnectionID else {
        throw .invalidConfiguration
      }
    } else if clientHello.connectionID != nil {
      throw .invalidConfiguration
    }
    guard clientHello.namedGroup == keyExchange.namedGroup else {
      throw .keyExchange(
        .unexpectedNamedGroup(
          expected: keyExchange.namedGroup,
          actual: clientHello.namedGroup
        ))
    }
    if let applicationProtocolSelector {
      let selected: TLS13ApplicationProtocol
      do {
        selected = try applicationProtocolSelector.select(
          from: clientHello.applicationProtocols
        )
      } catch let error {
        throw .applicationProtocol(error)
      }
      guard clientHello.applicationProtocols.contains(selected) else {
        throw .applicationProtocol(.noApplicationProtocol)
      }
      selectedApplicationProtocol = selected
    } else if !clientHello.applicationProtocols.isEmpty {
      throw .applicationProtocol(.noApplicationProtocol)
    }
    switch (localTransportParameters, clientHello.transportParameters) {
    case (.none, .none):
      break
    case (.some, .some(let received)):
      peerTransportParameters = received
    case (.some, .none):
      throw .missingTransportParameters
    case (.none, .some):
      throw .unexpectedTransportParameters
    }
    try negotiateDTLSSRTP(offer: clientHello.useSRTP)
    cipherSuite = clientHello.cipherSuite
    resumedHandshake = try acceptResumption(
      clientHello: clientHello,
      encodedClientHello: authenticatedClientHello.span,
      binderTranscriptIncludesRetry: binderTranscriptIncludesRetry
    )
    try negotiateCertificateTypes(
      clientHello: clientHello,
      requiresServerCredential: !resumedHandshake
    )
    if !resumedHandshake {
      try validateServerCredentialSupport(clientHello)
    }
    try decideEarlyData(
      clientHello: clientHello,
      binderTranscriptIncludesRetry: binderTranscriptIncludesRetry
    )
    try appendTranscript(authenticatedClientHello.span)

    let clientHelloHash = try transcriptDigest()
    let schedule: TLS13KeySchedule
    if resumedHandshake {
      guard resumptionPSK != nil else { throw .invalidState }
      do {
        schedule = try resumptionPSK!.withBorrowedBytes { bytes in
          try TLS13KeySchedule(cipherSuite: cipherSuite, preSharedKey: bytes)
        }
      } catch {
        throw mapHandshakeEngineError(error)
      }
    } else {
      schedule = try engineTry {
        try TLS13KeySchedule(
          cipherSuite: cipherSuite,
          preSharedKey: ContiguousArray<UInt8>().span
        )
      }
    }
    let earlyTrafficSecret: TLS13EarlyTrafficSecret?
    if shouldDeriveEarlyTrafficSecret {
      do {
        earlyTrafficSecret = try schedule.makeClientEarlyTrafficSecret(
          transcriptHash: clientHelloHash.span
        )
      } catch let error {
        throw .keySchedule(error)
      }
    } else {
      earlyTrafficSecret = nil
    }

    let keyExchangeResult: TLS13ServerKeyExchangeResult
    do {
      keyExchangeResult = try keyExchange.accept(
        clientShare: clientHello.keyShare.span,
        using: keyExchangeEntropy
      )
    } catch let error {
      throw .keyExchange(error)
    }
    let draftServerHello: OwnedBytes
    do {
      draftServerHello = try TLS13HandshakeCodec.makeServerHello(
        random: random.span,
        namedGroup: keyExchange.namedGroup,
        keyShare: keyExchangeResult.serverShare.span,
        cipherSuite: cipherSuite,
        selectedPreSharedKey: resumedHandshake,
        connectionID: localConnectionID?.span,
        encoding: handshakeEncoding
      )
    } catch let error {
      throw .handshake(error)
    }
    var serverHello = draftServerHello
    if echAccepted {
      let confirmation: OwnedBytes
      do {
        confirmation = try ECHAcceptanceConfirmation.compute(
          innerClientHello: authenticatedClientHello.span,
          serverHello: draftServerHello.span,
          cipherSuite: cipherSuite,
          handshakeEncoding: handshakeEncoding
        )
      } catch let error {
        throw .ech(error)
      }
      var confirmedRandom = copyBytes(random.span)
      var index = 0
      while index < ECHAcceptanceConfirmation.byteCount {
        confirmedRandom[confirmedRandom.count - ECHAcceptanceConfirmation.byteCount + index] =
          confirmation[index]
        index += 1
      }
      do {
        serverHello = try TLS13HandshakeCodec.makeServerHello(
          random: confirmedRandom.span,
          namedGroup: keyExchange.namedGroup,
          keyShare: keyExchangeResult.serverShare.span,
          cipherSuite: cipherSuite,
          selectedPreSharedKey: resumedHandshake,
          connectionID: localConnectionID?.span,
          encoding: handshakeEncoding
        )
      } catch let error {
        throw .handshake(error)
      }
    }
    try appendTranscript(serverHello.span)
    let helloHash = try transcriptDigest()
    // Swift 6.4's move-only checker cannot lower a noncopyable
    // TLS13HandshakeSecrets return directly from the SecretBytes borrow closure.
    // Materialize only the 32/64-byte combined secret, then wipe it after HKDF.
    var sharedBytes = ContiguousArray<UInt8>()
    defer { wipe(&sharedBytes) }
    keyExchangeResult.sharedSecret.withBorrowedBytes { shared in
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
        transcriptHash: helloHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let handshakeExport: TLS13TrafficSecretPair
    do {
      handshakeExport = try secrets.exportTrafficSecrets()
    } catch {
      throw .malformedInput
    }
    handshakeSecrets = consume secrets

    if usesExternalServerCredential, !resumedHandshake {
      return .suspended(
        try suspendForServerSignature(
          serverHello: serverHello,
          earlyTrafficSecret: earlyTrafficSecret,
          handshakeSecrets: handshakeExport
        )
      )
    }
    let serverFlight = try makeServerFlightMessages()
    let applicationHash = try transcriptDigest()
    guard handshakeSecrets != nil else { throw .invalidState }
    let derived: TLS13ApplicationSecrets
    do {
      derived = try handshakeSecrets!.makeApplicationSecrets(
        transcriptHash: applicationHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let applicationExport: TLS13TrafficSecretPair
    do {
      applicationExport = try derived.exportTrafficSecrets()
    } catch {
      throw .malformedInput
    }
    applicationSecrets = consume derived
    phase = earlyDataStateStorage == .accepted && handshakeEncoding == .tls13
      ? .awaitingEndOfEarlyData
      : .awaitingClientFinished
    return .output(
      try makeServerFlightOutput(
        serverHello: serverHello,
        encryptedFlight: serverFlight,
        earlyTrafficSecret: earlyTrafficSecret,
        handshakeSecrets: handshakeExport,
        applicationSecrets: applicationExport
      )
    )
  }

  private mutating func suspendForServerSignature(
    serverHello: consuming OwnedBytes,
    earlyTrafficSecret: consuming TLS13EarlyTrafficSecret?,
    handshakeSecrets exportedHandshakeSecrets: consuming TLS13TrafficSecretPair
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest {
    guard usesExternalServerCredential,
      let credential = externalServerCredential,
      pendingServerSignature == nil,
      handshakeSecrets != nil
    else {
      throw .invalidState
    }
    var messages = ContiguousArray<OwnedBytes>()
    let encryptedExtensions = try engineTry {
      try TLS13HandshakeCodec.makeEncryptedExtensions(
        applicationProtocol: selectedApplicationProtocol,
        transportParameters: localTransportParameters?.span,
        useSRTP: makeDTLSSRTPSelection(),
        echRetryConfigurations: echRejected ? echRetryConfigurations : nil,
        acceptsEarlyData: earlyDataStateStorage == .accepted,
        clientCertificateType: selectedClientCertificateTypeExtension,
        serverCertificateType: selectedServerCertificateTypeExtension,
        encoding: handshakeEncoding
      )
    }
    try appendTranscript(encryptedExtensions.span)
    messages.append(encryptedExtensions)
    if mainHandshakeClientAuthentication != nil {
      let certificateRequest = try engineTry {
        try TLS13HandshakeCodec.makeCertificateRequest(
          signatureSchemes: [
            .ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519,
          ],
          certificateCompressionAlgorithms:
            advertisedCertificateCompressionAlgorithms,
          delegatedCredentialAlgorithms:
            advertisedDelegatedCredentialAlgorithms
        )
      }
      try appendTranscript(certificateRequest.span)
      messages.append(certificateRequest)
    }
    let uncompressedCertificateMessage = try makeExternalCredentialCertificateMessage(
      credential
    )
    let certificateMessage = try compressCertificateMessageIfUseful(
      uncompressedCertificateMessage,
      peerAlgorithms: peerCertificateCompressionAlgorithms
    )
    try appendTranscript(certificateMessage.span)
    messages.append(certificateMessage)
    let transcriptHash = try transcriptDigest()
    let signedMessage = TLS13HandshakeWire.certificateVerifyInput(
      role: .server,
      transcriptHash: transcriptHash.span
    )
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .signature)
    } catch let error {
      throw .capability(error)
    }
    pendingServerSignature = PendingServerSignature(
      token: token,
      serverHello: serverHello,
      encryptedFlightPrefix: messages,
      signedMessage: signedMessage
    )
    pendingServerEarlyTrafficSecret = consume earlyTrafficSecret
    pendingServerHandshakeSecrets = consume exportedHandshakeSecrets
    phase = .suspendedForSignature
    return .signature(
      TLS13SignatureRequest(
        token: token,
        role: .server,
        credentialIdentifier: credential.identifier,
        signatureScheme: credential.signatureScheme,
        message: signedMessage
      )
    )
  }

  private mutating func resumeServerSignature(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard pendingServerSignature != nil,
      let credential = externalServerCredential
    else {
      throw .capability(.wrongState)
    }
    switch response {
    case .signatureRejected(let token):
      pendingServerSignature = nil
      _ = pendingServerEarlyTrafficSecret.take()
      _ = pendingServerHandshakeSecrets.take()
      capabilitySequencer.complete(token)
      phase = .failed
      throw .capability(.signatureRejected(.server))

    case .signature(let token, let signature):
      guard let pending = pendingServerSignature else {
        throw .capability(.wrongState)
      }
      pendingServerSignature = nil
      let pendingEarlyTrafficSecret = pendingServerEarlyTrafficSecret.take()
      guard let pendingHandshakeSecrets = pendingServerHandshakeSecrets.take() else {
        phase = .failed
        throw .invalidState
      }
      do {
        let publicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: subjectPublicKeyInfo(for: credential)
        )
        let certificateVerifyValue = TLS13CertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature
        )
        let verified = try publicKey.verify(
          certificateVerifyValue,
          signedMessage: pending.signedMessage.span
        )
        guard verified else { throw TLS13HandshakeEngineError.certificateVerifyFailure }
        let certificateVerify = try TLS13HandshakeCodec.makeCertificateVerify(
          signatureScheme: credential.signatureScheme,
          signature: signature.span
        )
        try appendTranscript(certificateVerify.span)
        var messages = pending.encryptedFlightPrefix
        messages.append(certificateVerify)

        let finishedHash = try transcriptDigest()
        guard handshakeSecrets != nil else {
          throw TLS13HandshakeEngineError.invalidState
        }
        let verifyData: OwnedBytes
        do {
          verifyData = try handshakeSecrets!.makeServerFinishedVerifyData(
            transcriptHash: finishedHash.span
          )
        } catch let error {
          throw TLS13HandshakeEngineError.keySchedule(error)
        }
        let finishedMessage = try TLS13HandshakeCodec.makeFinished(
          verifyData: verifyData.span
        )
        try appendTranscript(finishedMessage.span)
        messages.append(finishedMessage)

        let applicationHash = try transcriptDigest()
        let derived: TLS13ApplicationSecrets
        do {
          derived = try handshakeSecrets!.makeApplicationSecrets(
            transcriptHash: applicationHash.span
          )
        } catch let error {
          throw TLS13HandshakeEngineError.keySchedule(error)
        }
        let applicationExport: TLS13TrafficSecretPair
        do {
          applicationExport = try derived.exportTrafficSecrets()
        } catch {
          throw TLS13HandshakeEngineError.malformedInput
        }
        applicationSecrets = consume derived
        capabilitySequencer.complete(token)
        phase = earlyDataStateStorage == .accepted && handshakeEncoding == .tls13
          ? .awaitingEndOfEarlyData
          : .awaitingClientFinished
        return .output(
          try makeServerFlightOutput(
            serverHello: pending.serverHello,
            encryptedFlight: messages,
            earlyTrafficSecret: pendingEarlyTrafficSecret,
            handshakeSecrets: pendingHandshakeSecrets,
            applicationSecrets: applicationExport
          )
        )
      } catch let error as TLS13HandshakeEngineError {
        phase = .failed
        throw error
      } catch let error as X509CertificateError {
        phase = .failed
        throw .certificate(error)
      } catch {
        phase = .failed
        throw mapHandshakeEngineError(error)
      }

    case .peerTrustAccepted, .peerTrustRejected, .credentialSelected,
      .credentialUnavailable:
      throw .capability(.wrongState)
    }
  }

  private mutating func makeServerFlightMessages()
    throws(TLS13HandshakeEngineError) -> ContiguousArray<OwnedBytes>
  {
    guard handshakeSecrets != nil else { throw .invalidState }
    let certificateEntries = try serverCredential.certificateEntries()
    var messages = ContiguousArray<OwnedBytes>()
    let encryptedExtensions = try engineTry {
      try TLS13HandshakeCodec.makeEncryptedExtensions(
        applicationProtocol: selectedApplicationProtocol,
        transportParameters: localTransportParameters?.span,
        useSRTP: makeDTLSSRTPSelection(),
        echRetryConfigurations: echRejected ? echRetryConfigurations : nil,
        acceptsEarlyData: earlyDataStateStorage == .accepted,
        clientCertificateType: selectedClientCertificateTypeExtension,
        serverCertificateType: selectedServerCertificateTypeExtension,
        encoding: handshakeEncoding
      )
    }
    try appendTranscript(encryptedExtensions.span)
    messages.append(encryptedExtensions)
    if !resumedHandshake {
      if mainHandshakeClientAuthentication != nil {
        let certificateRequest = try engineTry {
          try TLS13HandshakeCodec.makeCertificateRequest(
            signatureSchemes: [
              .ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519,
            ],
            certificateCompressionAlgorithms:
              advertisedCertificateCompressionAlgorithms,
            delegatedCredentialAlgorithms:
              advertisedDelegatedCredentialAlgorithms
          )
        }
        try appendTranscript(certificateRequest.span)
        messages.append(certificateRequest)
      }
      let uncompressedCertificateMessage = try engineTry {
        try TLS13HandshakeCodec.makeCertificate(entries: certificateEntries)
      }
      let certificateMessage = try compressCertificateMessageIfUseful(
        uncompressedCertificateMessage,
        peerAlgorithms: peerCertificateCompressionAlgorithms
      )
      try appendTranscript(certificateMessage.span)
      messages.append(certificateMessage)
      let hash = try transcriptDigest()
      let signed = TLS13HandshakeWire.certificateVerifyInput(
        role: .server,
        transcriptHash: hash.span
      )
      let wireSignature = try serverCredential.sign(message: signed.span)
      let certificateVerify = try makeCertificateVerifyMessage(
        signatureScheme: try serverCredential.signatureScheme(),
        signature: wireSignature
      )
      try appendTranscript(certificateVerify.span)
      messages.append(certificateVerify)
    }
    let finishedHash = try transcriptDigest()
    let verifyData: OwnedBytes
    do {
      verifyData = try handshakeSecrets!.makeServerFinishedVerifyData(
        transcriptHash: finishedHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    let finishedMessage: OwnedBytes
    do {
      finishedMessage = try TLS13HandshakeCodec.makeFinished(
        verifyData: verifyData.span
      )
    } catch {
      throw mapHandshakeEngineError(error)
    }
    try appendTranscript(finishedMessage.span)
    messages.append(finishedMessage)
    return messages
  }

  private mutating func receiveClientFlightMessage(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard !message.isEmpty else { throw .malformedInput }
    switch message[0] {
    case TLS13HandshakeCodec.certificateType,
      TLS13HandshakeCodec.compressedCertificateType:
      guard let clientAuthentication = mainHandshakeClientAuthentication,
        !resumedHandshake,
        !sawClientCertificate,
        !sawClientCertificateVerify
      else {
        throw .malformedInput
      }
      let certificateMessage = try parsePeerCertificateMessage(message)
      guard certificateMessage.requestContext.isEmpty else {
        throw .malformedInput
      }
      if certificateMessage.entries.isEmpty {
        guard clientAuthentication.requirement == .optional else {
          throw .clientCertificateRequired
        }
        validatedClientCertificate = nil
        validatedClientPublicKey = nil
      } else {
        guard let validator = clientAuthentication.validator else {
          throw .capability(.wrongState)
        }
        let validated: TLS13ValidatedClientCertificate
        do {
          validated = try validator.validate(
            certificateMessage,
            at: verificationInstant
          )
        } catch let error {
          throw .clientCertificateValidation(error)
        }
        let publicKey: TLS13CertificateVerificationKey
        do {
          let activeSubjectPublicKeyInfo: SubjectPublicKeyInfo
          if certificateMessage.entries.first?.delegatedCredential != nil {
            activeSubjectPublicKeyInfo = try
              TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
                for: certificateMessage,
                role: .client,
                signatureSchemes:
                  TLS13DelegatedCredentialProcessor.signatureSchemes,
                delegatedCredentialAlgorithms:
                  advertisedDelegatedCredentialAlgorithms,
                at: verificationInstant
              )
          } else {
            activeSubjectPublicKeyInfo = validated.leafSubjectPublicKeyInfo
          }
          publicKey = try TLS13CertificateVerificationKey(
            subjectPublicKeyInfo: activeSubjectPublicKeyInfo
          )
        } catch let error as TLS13HandshakeEngineError {
          throw error
        } catch {
          throw .certificateVerificationFailed
        }
        validatedClientCertificate = validated
        validatedClientPublicKey = publicKey
      }
      try appendTranscript(message)
      sawClientCertificate = true
      return try makeOutput(bytes: OwnedBytes(), actions: [])

    case TLS13HandshakeCodec.certificateVerifyType:
      guard mainHandshakeClientAuthentication != nil,
        sawClientCertificate,
        !sawClientCertificateVerify,
        let publicKey = validatedClientPublicKey
      else {
        throw .malformedInput
      }
      let certificateVerify = try engineTry {
        try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message)
      }
      let transcriptHash = try transcriptDigest()
      let signed = TLS13HandshakeWire.certificateVerifyInput(
        role: .client,
        transcriptHash: transcriptHash.span
      )
      let verified: Bool
      do {
        verified = try publicKey.verify(
          certificateVerify,
          signedMessage: signed.span
        )
      } catch {
        throw .certificateVerifyFailure
      }
      guard verified else { throw .certificateVerifyFailure }
      try appendTranscript(message)
      sawClientCertificateVerify = true
      return try makeOutput(bytes: OwnedBytes(), actions: [])

    case TLS13HandshakeCodec.finishedType:
      if let clientAuthentication = mainHandshakeClientAuthentication {
        guard sawClientCertificate else {
          if clientAuthentication.requirement == .required {
            throw .clientCertificateRequired
          }
          throw .malformedInput
        }
        if validatedClientCertificate != nil {
          guard sawClientCertificateVerify else {
            throw .certificateVerifyFailure
          }
        } else {
          guard clientAuthentication.requirement == .optional,
            !sawClientCertificateVerify
          else {
            throw .clientCertificateRequired
          }
        }
      }
      return try receiveClientFinished(message)

    default:
      throw .handshake(.unexpectedMessage(type: message[0]))
    }
  }

  private mutating func receiveClientFinished(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard !message.isEmpty,
      message[0] == TLS13HandshakeCodec.finishedType
    else {
      throw .malformedInput
    }
    let finished = try engineTry {
      try TLS13HandshakeCodec.parseFinished(
        message,
        hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
      )
    }
    let hash = try transcriptDigest()
    guard let secrets = handshakeSecrets.take() else { throw .invalidState }
    let expected: OwnedBytes
    do {
      expected = try secrets.makeClientFinishedVerifyData(transcriptHash: hash.span)
    } catch let error {
      throw .keySchedule(error)
    }
    guard ConstantTime.equal(finished.span, expected.span) else {
      throw .certificateVerifyFailure
    }
    try appendTranscript(message)
    let completedHash = try transcriptDigest()
    let resumption: TLS13ResumptionMasterSecret
    do {
      resumption = try secrets.makeResumptionMasterSecret(
        transcriptHash: completedHash.span
      )
    } catch let error {
      throw .keySchedule(error)
    }
    resumptionMasterSecret = consume resumption
    phase = .established
    return try makeOutput(
      bytes: OwnedBytes(),
      actions: [.handshakeComplete, .handshakeConfirmed]
    )
  }

  private mutating func receivePostHandshakeClientAuthenticationMessage(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    guard let clientAuthentication,
      clientAuthentication.timing.includesPostHandshake,
      let requestContext = postHandshakeRequestContext,
      postHandshakeTranscript != nil,
      !message.isEmpty
    else {
      throw .invalidState
    }
    switch message[0] {
    case TLS13HandshakeCodec.certificateType,
      TLS13HandshakeCodec.compressedCertificateType:
      guard !postHandshakeSawClientCertificate,
        !postHandshakeSawClientCertificateVerify
      else {
        throw .malformedInput
      }
      let certificateMessage = try parsePeerCertificateMessage(message)
      guard certificateMessage.requestContext == requestContext else {
        throw .malformedInput
      }
      if certificateMessage.entries.isEmpty {
        guard clientAuthentication.requirement == .optional else {
          throw .clientCertificateRequired
        }
        postHandshakeValidatedClientCertificate = nil
        postHandshakeValidatedClientPublicKey = nil
      } else {
        guard let validator = clientAuthentication.validator else {
          throw .capability(.wrongState)
        }
        let validated: TLS13ValidatedClientCertificate
        do {
          validated = try validator.validate(
            certificateMessage,
            at: verificationInstant
          )
        } catch let error {
          throw .clientCertificateValidation(error)
        }
        let activeSubjectPublicKeyInfo: SubjectPublicKeyInfo
        do {
          activeSubjectPublicKeyInfo = try subjectPublicKeyInfo(
            for: certificateMessage
          )
        } catch {
          throw .certificateVerificationFailed
        }
        let publicKey: TLS13CertificateVerificationKey
        do {
          publicKey = try TLS13CertificateVerificationKey(
            subjectPublicKeyInfo: activeSubjectPublicKeyInfo
          )
        } catch {
          throw .certificateVerificationFailed
        }
        postHandshakeValidatedClientCertificate = validated
        postHandshakeValidatedClientPublicKey = publicKey
      }
      try appendPostHandshakeTranscript(message)
      postHandshakeSawClientCertificate = true
      return try makeOutput(bytes: OwnedBytes(), actions: [])

    case TLS13HandshakeCodec.certificateVerifyType:
      guard postHandshakeSawClientCertificate,
        !postHandshakeSawClientCertificateVerify,
        let publicKey = postHandshakeValidatedClientPublicKey
      else {
        throw .malformedInput
      }
      let certificateVerify = try engineTry {
        try TLS13HandshakeCodec.parseCertificateVerifyWithScheme(message)
      }
      let transcriptHash = try postHandshakeTranscriptDigest()
      let signed = TLS13HandshakeWire.certificateVerifyInput(
        role: .client,
        transcriptHash: transcriptHash.span
      )
      let verified: Bool
      do {
        verified = try publicKey.verify(
          certificateVerify,
          signedMessage: signed.span
        )
      } catch {
        throw .certificateVerifyFailure
      }
      guard verified else { throw .certificateVerifyFailure }
      try appendPostHandshakeTranscript(message)
      postHandshakeSawClientCertificateVerify = true
      return try makeOutput(bytes: OwnedBytes(), actions: [])

    case TLS13HandshakeCodec.finishedType:
      guard postHandshakeSawClientCertificate else {
        throw .malformedInput
      }
      if postHandshakeValidatedClientCertificate != nil {
        guard postHandshakeSawClientCertificateVerify else {
          throw .certificateVerifyFailure
        }
      } else {
        guard clientAuthentication.requirement == .optional,
          !postHandshakeSawClientCertificateVerify
        else {
          throw .clientCertificateRequired
        }
      }
      let finished = try engineTry {
        try TLS13HandshakeCodec.parseFinished(
          message,
          hashByteCount: TLS13KeySchedule.hashByteCount(for: cipherSuite)
        )
      }
      let transcriptHash = try postHandshakeTranscriptDigest()
      guard applicationSecrets != nil else { throw .invalidState }
      let expected: OwnedBytes
      do {
        expected = try applicationSecrets!.makeClientFinishedVerifyData(
          transcriptHash: transcriptHash.span
        )
      } catch let error {
        throw .keySchedule(error)
      }
      guard ConstantTime.equal(finished.span, expected.span) else {
        throw .certificateVerifyFailure
      }
      try appendPostHandshakeTranscript(message)
      if let validated = postHandshakeValidatedClientCertificate {
        validatedClientCertificate = validated
        validatedClientPublicKey = postHandshakeValidatedClientPublicKey
        sawClientCertificate = true
        sawClientCertificateVerify = true
      }
      clearPostHandshakeClientAuthentication()
      phase = .established
      return try makeOutput(bytes: OwnedBytes(), actions: [])

    default:
      throw .handshake(.unexpectedMessage(type: message[0]))
    }
  }

  private mutating func suspendForPostHandshakeClientTrust(
    encodedMessage: Span<UInt8>,
    certificateMessage: TLS13CertificateMessage
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest {
    guard case .established = phase,
      let clientAuthentication,
      clientAuthentication.timing.includesPostHandshake,
      clientAuthentication.validator == nil,
      let requestContext = postHandshakeRequestContext,
      certificateMessage.requestContext == requestContext,
      !certificateMessage.entries.isEmpty,
      !postHandshakeSawClientCertificate,
      !postHandshakeSawClientCertificateVerify,
      pendingPostHandshakeClientTrust == nil
    else {
      throw .invalidState
    }
    let token: TLS13CapabilityToken
    do {
      token = try capabilitySequencer.issue(kind: .peerTrustEvaluation)
    } catch let error {
      throw .capability(error)
    }
    pendingPostHandshakeClientTrust = PendingClientTrust(
      token: token,
      encodedMessage: OwnedBytes(copying: encodedMessage),
      certificateMessage: certificateMessage
    )
    phase = .suspendedForPostHandshakePeerTrust
    return .peerTrustEvaluation(
      TLS13PeerTrustEvaluationRequest(
        token: token,
        peer: .client,
        certificateMessage: certificateMessage,
        serverName: nil,
        verificationInstant: verificationInstant
      )
    )
  }

  private mutating func resumePostHandshakePeerTrust(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreTransition {
    guard let pending = pendingPostHandshakeClientTrust else {
      throw .capability(.wrongState)
    }
    switch response {
    case .peerTrustRejected(let token):
      capabilitySequencer.complete(token)
      pendingPostHandshakeClientTrust = nil
      clearPostHandshakeClientAuthentication()
      phase = .failed
      throw .capability(.peerTrustRejected(.client))

    case .peerTrustAccepted(let token):
      do {
        let activeSubjectPublicKeyInfo = try subjectPublicKeyInfo(
          for: pending.certificateMessage
        )
        let publicKey = try TLS13CertificateVerificationKey(
          subjectPublicKeyInfo: activeSubjectPublicKeyInfo
        )
        let leafSubjectPublicKeyInfo: SubjectPublicKeyInfo
        switch pending.certificateMessage.certificateType {
        case .x509:
          let leaf = pending.certificateMessage.entries[0].certificate
          leafSubjectPublicKeyInfo = try X509Certificate(der: leaf.span)
            .subjectPublicKeyInfo
        case .rawPublicKey:
          leafSubjectPublicKeyInfo = activeSubjectPublicKeyInfo
        }
        postHandshakeValidatedClientCertificate =
          TLS13ValidatedClientCertificate(
            certificateMessage: pending.certificateMessage,
            leafSubjectPublicKeyInfo: leafSubjectPublicKeyInfo
          )
        postHandshakeValidatedClientPublicKey = publicKey
        try appendPostHandshakeTranscript(pending.encodedMessage.span)
        postHandshakeSawClientCertificate = true
        capabilitySequencer.complete(token)
        pendingPostHandshakeClientTrust = nil
        phase = .established
        return .output(try makeOutput(bytes: OwnedBytes(), actions: []))
      } catch let error as TLS13HandshakeEngineError {
        pendingPostHandshakeClientTrust = nil
        phase = .failed
        throw error
      } catch let error as X509CertificateError {
        pendingPostHandshakeClientTrust = nil
        phase = .failed
        throw .certificate(error)
      } catch {
        pendingPostHandshakeClientTrust = nil
        phase = .failed
        throw .certificateVerificationFailed
      }

    case .credentialSelected, .credentialUnavailable, .signature,
      .signatureRejected:
      throw .capability(.wrongState)
    }
  }

  private mutating func appendPostHandshakeTranscript(
    _ message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) {
    guard var authenticationTranscript = postHandshakeTranscript.take() else {
      throw .invalidState
    }
    do {
      try authenticationTranscript.append(message)
      postHandshakeTranscript = consume authenticationTranscript
    } catch let error {
      throw .handshake(error)
    }
  }

  private mutating func postHandshakeTranscriptDigest()
    throws(TLS13HandshakeEngineError) -> OwnedBytes
  {
    guard let authenticationTranscript = postHandshakeTranscript.take() else {
      throw .invalidState
    }
    do {
      let digest = try authenticationTranscript.digest(for: cipherSuite)
      postHandshakeTranscript = consume authenticationTranscript
      return digest
    } catch let error {
      postHandshakeTranscript = consume authenticationTranscript
      throw .handshake(error)
    }
  }

  private mutating func clearPostHandshakeClientAuthentication() {
    postHandshakeTranscript = nil
    postHandshakeRequestContext = nil
    postHandshakeValidatedClientCertificate = nil
    postHandshakeValidatedClientPublicKey = nil
    postHandshakeSawClientCertificate = false
    postHandshakeSawClientCertificateVerify = false
    pendingPostHandshakeClientTrust = nil
  }

  private func acceptResumption(
    clientHello: TLS13ClientHello,
    encodedClientHello: Span<UInt8>,
    binderTranscriptIncludesRetry: Bool
  ) throws(TLS13HandshakeEngineError) -> Bool {
    guard let configuredIdentity = resumptionIdentity,
      resumptionPSK != nil,
      let issuedAt = resumptionIssuedAt,
      let lifetime = resumptionLifetime,
      let ageAdd = resumptionAgeAdd
    else {
      return false
    }
    let truncated: OwnedBytes
    let binderHash: OwnedBytes
    do {
      truncated = try TLS13HandshakeCodec.truncatedClientHelloForBinder(
        encodedClientHello,
        encoding: handshakeEncoding
      )
      if binderTranscriptIncludesRetry {
        binderHash = try transcript.digest(
          appending: truncated.span,
          for: clientHello.cipherSuite
        )
      } else {
        var binderTranscript = try TLS13Transcript()
        try binderTranscript.append(truncated.span)
        binderHash = try binderTranscript.digest(for: clientHello.cipherSuite)
      }
    } catch let error as TLS13HandshakeError {
      throw .handshake(error)
    } catch {
      throw .preSharedKey(.derivationFailed)
    }
    return try verifyCoreResumption(
      clientHello: clientHello,
      binderTranscriptHash: binderHash,
      configuredIdentity: configuredIdentity,
      preSharedKey: resumptionPSK!,
      verificationInstant: verificationInstant,
      issuedAt: issuedAt,
      lifetime: lifetime,
      ageAdd: ageAdd,
      toleranceMilliseconds: resumptionAgeToleranceMilliseconds
    )
  }

  private mutating func decideEarlyData(
    clientHello: TLS13ClientHello,
    binderTranscriptIncludesRetry: Bool
  ) throws(TLS13HandshakeEngineError) {
    guard clientHello.offersEarlyData else { return }
    guard handshakeEncoding != .dtls13 else { throw .malformedInput }
    earlyDataStateStorage = .rejected
    shouldDeriveEarlyTrafficSecret = !binderTranscriptIncludesRetry && resumedHandshake
    guard !binderTranscriptIncludesRetry,
      resumedHandshake,
      resumptionMaximumEarlyDataByteCount > 0,
      selectedApplicationProtocol == resumptionApplicationProtocol,
      let earlyDataConfiguration,
      let identity = clientHello.preSharedKey?.identities.first
    else {
      return
    }
    let context = TLS13EarlyDataReplayContext(
      ticketIdentity: identity.identity.span,
      obfuscatedTicketAge: identity.obfuscatedTicketAge,
      applicationProtocol: selectedApplicationProtocol
    )
    let decision: TLS13EarlyDataReplayDecision
    do {
      decision = try earlyDataConfiguration.replayProtector.evaluate(context)
    } catch {
      throw .earlyDataReplayProtectionFailed
    }
    guard decision == .accept else { return }
    earlyDataStateStorage = .accepted
    earlyDataByteLimitStorage = Swift.min(
      resumptionMaximumEarlyDataByteCount,
      earlyDataConfiguration.maximumByteCount
    )
  }

  private func validateRetryEligibleClientHello(
    _ clientHello: TLS13ClientHello
  ) throws(TLS13HandshakeEngineError) {
    if let expectedPeerConnectionID {
      guard clientHello.connectionID == expectedPeerConnectionID else {
        throw .invalidConfiguration
      }
    } else if clientHello.connectionID != nil {
      throw .invalidConfiguration
    }
    guard clientHello.namedGroup == keyExchange.namedGroup else {
      throw .keyExchange(
        .unexpectedNamedGroup(
          expected: keyExchange.namedGroup,
          actual: clientHello.namedGroup
        )
      )
    }
    guard !availableServerCertificateTypes(for: clientHello).isEmpty else {
      throw .certificateVerificationFailed
    }
    if let clientAuthentication {
      let offeredClientCertificateTypes = clientHello.clientCertificateTypes.isEmpty
        ? ContiguousArray([TLS13CertificateType.x509])
        : clientHello.clientCertificateTypes
      guard offeredClientCertificateTypes.contains(
        clientAuthentication.certificateType
      ) else {
        throw .certificateVerificationFailed
      }
    }
    if !usesExternalServerCredential {
      try validateServerCredentialSupport(clientHello)
    }
  }

  private func validateServerCredentialSupport(
    _ clientHello: TLS13ClientHello
  ) throws(TLS13HandshakeEngineError) {
    let signatureScheme = try activeServerSignatureScheme()
    if let delegatedCredential = try activeServerDelegatedCredential() {
      guard clientHello.delegatedCredentialAlgorithms.contains(
        signatureScheme
      ), clientHello.signatureSchemes.contains(
        delegatedCredential.delegationAlgorithm
      ) else {
        throw .certificateVerifyFailure
      }
    } else {
      guard clientHello.signatureSchemes.contains(signatureScheme) else {
        throw .certificateVerifyFailure
      }
    }
  }

  private func activeServerDelegatedCredential()
    throws(TLS13HandshakeEngineError) -> TLS13DelegatedCredential?
  {
    if usesExternalServerCredential {
      guard let credential = externalServerCredential else {
        throw .invalidState
      }
      return credential.certificateEntries.first?.delegatedCredential
    }
    return try serverCredential.delegatedCredential()
  }

  private func availableServerCertificateTypes(
    for clientHello: TLS13ClientHello
  ) -> ContiguousArray<TLS13CertificateType> {
    let offered = clientHello.serverCertificateTypes.isEmpty
      ? ContiguousArray([TLS13CertificateType.x509])
      : clientHello.serverCertificateTypes
    var available = ContiguousArray<TLS13CertificateType>()
    available.reserveCapacity(offered.count)
    for certificateType in offered {
      if supportedServerCertificateTypes.contains(certificateType) {
        available.append(certificateType)
      }
    }
    return available
  }

  private mutating func negotiateCertificateTypes(
    clientHello: TLS13ClientHello,
    requiresServerCredential: Bool
  ) throws(TLS13HandshakeEngineError) {
    let available = availableServerCertificateTypes(for: clientHello)
    guard !available.isEmpty else {
      throw .certificateVerificationFailed
    }
    let selectedServerType: TLS13CertificateType
    if let externalServerCredential {
      guard available.contains(externalServerCredential.certificateType) else {
        throw .capability(.invalidCredential)
      }
      selectedServerType = externalServerCredential.certificateType
    } else if usesExternalServerCredential {
      guard !requiresServerCredential else { throw .invalidState }
      selectedServerType = available[0]
    } else {
      guard available.contains(.x509) else {
        throw .certificateVerificationFailed
      }
      selectedServerType = .x509
    }
    negotiatedServerCertificateType = selectedServerType
    selectedServerCertificateTypeExtension =
      clientHello.serverCertificateTypes.isEmpty ? nil : selectedServerType

    if let clientAuthentication {
      let offeredClientTypes = clientHello.clientCertificateTypes.isEmpty
        ? ContiguousArray([TLS13CertificateType.x509])
        : clientHello.clientCertificateTypes
      guard offeredClientTypes.contains(clientAuthentication.certificateType) else {
        throw .certificateVerificationFailed
      }
      negotiatedClientCertificateType = clientAuthentication.certificateType
      selectedClientCertificateTypeExtension =
        clientHello.clientCertificateTypes.isEmpty
        ? nil : clientAuthentication.certificateType
    } else {
      negotiatedClientCertificateType = .x509
      selectedClientCertificateTypeExtension = nil
    }
  }

  private borrowing func activeServerSignatureScheme()
    throws(TLS13HandshakeEngineError) -> TLS13SignatureScheme
  {
    if usesExternalServerCredential {
      guard let externalServerCredential else { throw .invalidState }
      return externalServerCredential.signatureScheme
    }
    return try serverCredential.signatureScheme()
  }

  private mutating func processClientHello(
    _ encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ECHProcessedClientHello {
    let containsECH: Bool
    do {
      containsECH = try ECHClientHelloCodec.containsOuterECH(
        encodedClientHello,
        encoding: handshakeEncoding
      )
    } catch let error {
      throw .ech(error)
    }
    guard containsECH else {
      return ECHProcessedClientHello(
        encoded: OwnedBytes(copying: encodedClientHello),
        echAccepted: false,
        echRejected: false
      )
    }
    guard var opener = echOpener.take() else {
      return ECHProcessedClientHello(
        encoded: OwnedBytes(copying: encodedClientHello),
        echAccepted: false,
        echRejected: true
      )
    }
    do {
      let opened = try opener.open(
        encodedClientHello,
        encoding: handshakeEncoding
      )
      echOpener = consume opener
      return ECHProcessedClientHello(
        encoded: opened.innerClientHello,
        echAccepted: true,
        echRejected: false
      )
    } catch let error {
      switch error {
      case .noCompatibleConfiguration, .payloadAuthenticationFailed, .hpke:
        echOpener = nil
        return ECHProcessedClientHello(
          encoded: OwnedBytes(copying: encodedClientHello),
          echAccepted: false,
          echRejected: true
        )
      default:
        echOpener = nil
        throw .ech(error)
      }
    }
  }

  private mutating func processRetriedClientHello(
    _ encodedClientHello: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ECHProcessedClientHello {
    if echAccepted {
      guard var opener = echOpener.take() else {
        throw .invalidState
      }
      do {
        let opened = try opener.open(
          encodedClientHello,
          encoding: handshakeEncoding
        )
        echOpener = consume opener
        return ECHProcessedClientHello(
          encoded: opened.innerClientHello,
          echAccepted: true,
          echRejected: false
        )
      } catch let error {
        echOpener = nil
        throw .ech(error)
      }
    }
    return ECHProcessedClientHello(
      encoded: OwnedBytes(copying: encodedClientHello),
      echAccepted: false,
      echRejected: echRejected
    )
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

  private mutating func negotiateDTLSSRTP(
    offer: DTLSSRTPUseSRTPData?
  ) throws(TLS13HandshakeEngineError) {
    switch (srtpConfiguration, offer) {
    case (.none, .none):
      return
    case (.none, .some):
      throw .srtp(.unexpectedExtension)
    case (.some, .none):
      throw .srtp(.missingExtension)
    case (.some(let configuration), .some(let offer)):
      var selected: DTLSSRTPProtectionProfile?
      for profile in configuration.protectionProfiles {
        if offer.protectionProfileIDs.contains(profile.rawValue) {
          selected = profile
          break
        }
      }
      guard let selected else {
        throw .srtp(.noSharedProtectionProfile)
      }
      negotiatedSRTPProtectionProfile = selected
      negotiatedSRTPMasterKeyIdentifier = configuration.echoesMasterKeyIdentifier
        ? offer.masterKeyIdentifier
        : OwnedBytes()
    }
  }

  private borrowing func makeDTLSSRTPSelection() -> DTLSSRTPUseSRTPData? {
    guard let profile = negotiatedSRTPProtectionProfile,
      let masterKeyIdentifier = negotiatedSRTPMasterKeyIdentifier
    else {
      return nil
    }
    return DTLSSRTPUseSRTPData(
      protectionProfiles: [profile],
      masterKeyIdentifier: masterKeyIdentifier
    )
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

  private func makeServerFlightOutput(
    serverHello: OwnedBytes,
    encryptedFlight: ContiguousArray<OwnedBytes>,
    earlyTrafficSecret: consuming TLS13EarlyTrafficSecret?,
    handshakeSecrets: consuming TLS13TrafficSecretPair,
    applicationSecrets: consuming TLS13TrafficSecretPair
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeCoreOutput {
    var storage = ContiguousArray<UInt8>()
    var messagesByteCount = 0
    for message in encryptedFlight { messagesByteCount += message.count }
    storage.reserveCapacity(serverHello.count + messagesByteCount)
    append(serverHello.span, to: &storage)
    for message in encryptedFlight { append(message.span, to: &storage) }
    let helloRange: ByteRange
    let flightRange: ByteRange
    do {
      helloRange = try ByteRange(offset: 0, count: serverHello.count)
      flightRange = try ByteRange(offset: serverHello.count, count: messagesByteCount)
    } catch let error {
      throw .output(error)
    }
    var actions: ContiguousArray<TLS13HandshakeCoreAction> = [
      .emitHandshakeBytes(epoch: .initial, bytes: helloRange)
    ]
    if earlyTrafficSecret != nil {
      let disposition: TLS13EarlyTrafficSecretDisposition =
        earlyDataStateStorage == .accepted ? .application : .discard
      actions.append(.installEarlyTrafficSecret(disposition: disposition))
    }
    if earlyDataStateStorage == .accepted {
      actions.append(.earlyDataAccepted)
    } else if earlyDataStateStorage == .rejected {
      actions.append(.earlyDataRejected)
    }
    actions.append(.installTrafficSecrets(epoch: .handshake))
    actions.append(.emitHandshakeBytes(epoch: .handshake, bytes: flightRange))
    actions.append(.installTrafficSecrets(epoch: .application))
    return try makeOutput(
      bytes: OwnedBytes(consuming: storage),
      actions: actions,
      earlyTrafficSecret: earlyTrafficSecret,
      handshakeSecrets: handshakeSecrets,
      applicationSecrets: applicationSecrets
    )
  }

  private func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }

  private func copyBytes(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(source.count)
    append(source, to: &result)
    return result
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

  private static func makeSingleCertificateEntry(
    certificateDER: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ContiguousArray<TLS13CertificateEntry> {
    do {
      return [try TLS13CertificateEntry(certificateDER: certificateDER)]
    } catch let error {
      throw .handshake(error)
    }
  }

  private static func validateCertificateEntries(
    _ entries: borrowing ContiguousArray<TLS13CertificateEntry>
  ) throws(TLS13HandshakeEngineError) -> X509Certificate {
    var leaf: X509Certificate?
    var index = 0
    while index < entries.count {
      let entry = entries[index]
      let certificate: X509Certificate
      do {
        certificate = try X509Certificate(der: entry.certificate.span)
      } catch let error {
        throw .certificate(error)
      }
      if index == 0 {
        leaf = certificate
      }
      if let response = entry.stapledOCSPResponse {
        do {
          _ = try OCSPResponse(der: response.span)
        } catch {
          throw .invalidConfiguration
        }
      }
      if let timestampList = entry.signedCertificateTimestampList {
        do {
          _ = try SignedCertificateTimestampList(encoded: timestampList.span)
        } catch {
          throw .invalidConfiguration
        }
      }
      index += 1
    }
    guard let leaf else { throw .invalidConfiguration }
    return leaf
  }
}

private enum TLS13ServerCredentialStorage: ~Copyable, Sendable {
  case local(
    certificateEntries: ContiguousArray<TLS13CertificateEntry>,
    signingKey: TLS13SigningKey
  )
  case external

  var isExternal: Bool {
    borrowing get {
      switch self {
      case .local: false
      case .external: true
      }
    }
  }

  borrowing func validatedLeaf(
    at instant: VerificationInstant
  ) throws(TLS13HandshakeEngineError) -> X509Certificate? {
    switch self {
    case .external:
      return nil
    case .local(let entries, let signingKey):
      guard !entries.isEmpty,
        entries.count <= TLS13CertificateMessage.maximumCertificateCount
      else {
        throw .invalidConfiguration
      }
      var leaf: X509Certificate?
      var index = 0
      while index < entries.count {
        let certificateBytes = entries[index].certificate
        let certificate: X509Certificate
        do {
          certificate = try X509Certificate(der: certificateBytes.span)
        } catch let error {
          throw .certificate(error)
        }
        if index == 0 { leaf = certificate }
        guard index == 0 || entries[index].delegatedCredential == nil else {
          throw .invalidConfiguration
        }
        if let response = entries[index].stapledOCSPResponse {
          do {
            _ = try OCSPResponse(der: response.span)
          } catch {
            throw .invalidConfiguration
          }
        }
        if let timestampList = entries[index].signedCertificateTimestampList {
          do {
            _ = try SignedCertificateTimestampList(encoded: timestampList.span)
          } catch {
            throw .invalidConfiguration
          }
        }
        index += 1
      }
      guard let leaf else { throw .invalidConfiguration }
      guard leaf.validity.contains(instant) else { throw .certificateNotValid }
      let activeSubjectPublicKeyInfo = try
        TLS13DelegatedCredentialProcessor.activeSubjectPublicKeyInfo(
          for: entries,
          role: .server,
          signatureSchemes:
            TLS13DelegatedCredentialProcessor.signatureSchemes,
          delegatedCredentialAlgorithms:
            TLS13DelegatedCredentialProcessor.delegatedCredentialAlgorithms,
          at: instant
        )
      guard signingKey.signatureScheme.matches(activeSubjectPublicKeyInfo) else {
        throw .invalidConfiguration
      }
      let publicBytes: ContiguousArray<UInt8>
      do {
        publicBytes = try signingKey.publicKeyBytes()
      } catch let error {
        throw .crypto(error)
      }
      let publicKey = OwnedBytes(consuming: publicBytes)
      let keyMatches = activeSubjectPublicKeyInfo.withPublicKeyBytes { key in
        ConstantTime.equal(key, publicKey.span)
      }
      guard keyMatches else { throw .certificateKeyMismatch }
      return leaf
    }
  }

  borrowing func certificateEntries()
    throws(TLS13HandshakeEngineError) -> ContiguousArray<TLS13CertificateEntry>
  {
    switch self {
    case .local(let entries, _): entries
    case .external: throw .invalidState
    }
  }

  borrowing func signatureScheme()
    throws(TLS13HandshakeEngineError) -> TLS13SignatureScheme
  {
    switch self {
    case .local(_, let signingKey): signingKey.signatureScheme
    case .external: throw .invalidState
    }
  }

  borrowing func delegatedCredential()
    throws(TLS13HandshakeEngineError) -> TLS13DelegatedCredential?
  {
    switch self {
    case .local(let entries, _):
      return entries.first?.delegatedCredential
    case .external:
      throw .invalidState
    }
  }

  borrowing func sign(
    message: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ContiguousArray<UInt8> {
    switch self {
    case .local(_, let signingKey):
      do {
        return try signingKey.sign(message: message)
      } catch let error {
        throw .signing(error)
      }
    case .external: throw .invalidState
    }
  }
}

private struct PendingClientTrust: Sendable {
  let token: TLS13CapabilityToken
  let encodedMessage: OwnedBytes
  let certificateMessage: TLS13CertificateMessage
}

private struct PendingServerCredentialSelection: Sendable {
  let token: TLS13CapabilityToken
  let processedClientHello: ECHProcessedClientHello
  let binderTranscriptIncludesRetry: Bool
  let signatureSchemes: ContiguousArray<TLS13SignatureScheme>
  let delegatedCredentialAlgorithms: ContiguousArray<TLS13SignatureScheme>
  let certificateTypes: ContiguousArray<TLS13CertificateType>
}

private struct PendingServerSignature: Sendable {
  let token: TLS13CapabilityToken
  let serverHello: OwnedBytes
  let encryptedFlightPrefix: ContiguousArray<OwnedBytes>
  let signedMessage: OwnedBytes
}

private struct ECHProcessedClientHello: Sendable {
  let encoded: OwnedBytes
  let echAccepted: Bool
  let echRejected: Bool
}

private func verifyCoreResumption(
  clientHello: TLS13ClientHello,
  binderTranscriptHash: OwnedBytes,
  configuredIdentity: OwnedBytes,
  preSharedKey: borrowing SecretBytes,
  verificationInstant: VerificationInstant,
  issuedAt: VerificationInstant,
  lifetime: UInt32,
  ageAdd: UInt32,
  toleranceMilliseconds: UInt32
) throws(TLS13HandshakeEngineError) -> Bool {
  guard let offered = clientHello.preSharedKey,
    offered.identities.count == 1,
    offered.binders.count == 1
  else {
    return false
  }
  let identity = offered.identities[0]
  let offeredBinder = offered.binders[0].value
  guard ConstantTime.equal(identity.identity.span, configuredIdentity.span),
    let expectedAge = expectedObfuscatedTicketAge(
      at: verificationInstant,
      issuedAt: issuedAt,
      lifetime: lifetime,
      ageAdd: ageAdd
    ),
    ticketAgeWithinTolerance(
      offered: identity.obfuscatedTicketAge,
      expected: expectedAge,
      toleranceMilliseconds: toleranceMilliseconds
    )
  else {
    return false
  }
  do {
    return try TLS13PSKBinder.verify(
      preSharedKey: preSharedKey,
      cipherSuite: clientHello.cipherSuite,
      transcriptHash: binderTranscriptHash.span,
      binder: offeredBinder.span
    )
  } catch let error as TLS13PSKError {
    throw .preSharedKey(error)
  } catch {
    throw .preSharedKey(.derivationFailed)
  }
}
