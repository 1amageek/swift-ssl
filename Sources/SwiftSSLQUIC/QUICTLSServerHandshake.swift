import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

/// QUIC server handshake driver composed from per-level CRYPTO streams and the
/// record-independent TLS 1.3 server core.
public struct QUICTLSServerHandshake: QUICTLSServerHandshaking, ~Copyable, Sendable {
  private var core: TLS13ServerHandshakeCore
  private var initialStream: QUICTLSHandshakeStream
  private var handshakeStream: QUICTLSHandshakeStream

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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
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
    maximumBufferedByteCount: Int = QUICCryptoStreamReassembler.defaultMaximumBufferedByteCount,
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
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
    return try make(
      core: core,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
  }

  private static func make(
    core: consuming TLS13ServerHandshakeCore,
    maximumBufferedByteCount: Int,
    maximumMessageByteCount: Int
  ) throws(QUICTLSHandshakeError) -> Self {
    let initial = try makeStream(
      level: .initial,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
    let handshake = try makeStream(
      level: .handshake,
      maximumBufferedByteCount: maximumBufferedByteCount,
      maximumMessageByteCount: maximumMessageByteCount
    )
    return Self(
      core: consume core,
      initialStream: initial,
      handshakeStream: handshake
    )
  }

  private init(
    core: consuming TLS13ServerHandshakeCore,
    initialStream: consuming QUICTLSHandshakeStream,
    handshakeStream: consuming QUICTLSHandshakeStream
  ) {
    self.core = core
    self.initialStream = initialStream
    self.handshakeStream = handshakeStream
  }

  public var isEstablished: Bool { core.isEstablished }

  public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
    core.negotiatedApplicationProtocol
  }

  public var receivedTransportParameters: OwnedBytes? {
    core.receivedTransportParameters
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

  public mutating func receiveCrypto(
    level: QUICTLSHandshakeInputLevel,
    offset: UInt64,
    bytes: Span<UInt8>
  ) throws(QUICTLSHandshakeError) {
    do {
      switch level {
      case .initial: try initialStream.receive(offset: offset, bytes: bytes)
      case .handshake: try handshakeStream.receive(offset: offset, bytes: bytes)
      }
    } catch let error {
      throw .stream(error)
    }
  }

  public mutating func processNextMessage(
    at level: QUICTLSHandshakeInputLevel
  ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput? {
    let produced: QUICTLSCoreTransition?
    do {
      switch level {
      case .initial:
        produced = try Self.transition(
          from: initialStream,
          core: &core,
          epoch: .initial
        )
      case .handshake:
        produced = try Self.transition(
          from: handshakeStream,
          core: &core,
          epoch: .handshake
        )
      }
    } catch let error {
      throw .stream(error)
    }
    guard let produced else { return nil }
    switch consume produced {
    case .failure(let error):
      throw .handshake(error)
    case .suspended:
      throw .handshake(.capability(.wrongState))
    case .success(let output):
      do {
        switch level {
        case .initial: try initialStream.discardNextMessage()
        case .handshake: try handshakeStream.discardNextMessage()
        }
      } catch let error {
        throw .stream(error)
      }
      return try QUICTLSCoreOutputAdapter.adapt(output, role: .server)
    }
  }

  public mutating func processNextMessageStep(
    at level: QUICTLSHandshakeInputLevel
  ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition? {
    let produced: QUICTLSCoreTransition?
    do {
      switch level {
      case .initial:
        produced = try Self.stepTransition(
          from: initialStream,
          core: &core,
          epoch: .initial
        )
      case .handshake:
        produced = try Self.stepTransition(
          from: handshakeStream,
          core: &core,
          epoch: .handshake
        )
      }
    } catch let error {
      throw .stream(error)
    }
    guard let produced else { return nil }
    switch consume produced {
    case .failure(let error):
      throw .handshake(error)
    case .success(let output):
      try discardNextMessage(at: level)
      return .output(try QUICTLSCoreOutputAdapter.adapt(output, role: .server))
    case .suspended(let request):
      try discardNextMessage(at: level)
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
      trafficSecret = try core.updateApplicationTrafficSecret(for: endpoint)
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

  private static func transition(
    from stream: borrowing QUICTLSHandshakeStream,
    core: inout TLS13ServerHandshakeCore,
    epoch: TLS13HandshakeEpoch
  ) throws(QUICTLSHandshakeStreamError) -> QUICTLSCoreTransition? {
    try stream.withNextMessage { message in
      do {
        return .success(
          try core.receiveHandshakeMessage(message, at: epoch)
        )
      } catch let error as TLS13HandshakeEngineError {
        return .failure(error)
      } catch {
        return .failure(.malformedInput)
      }
    }
  }

  private static func stepTransition(
    from stream: borrowing QUICTLSHandshakeStream,
    core: inout TLS13ServerHandshakeCore,
    epoch: TLS13HandshakeEpoch
  ) throws(QUICTLSHandshakeStreamError) -> QUICTLSCoreTransition? {
    try stream.withNextMessage { message in
      do {
        let transition = try core.receiveHandshakeMessageStep(
          message,
          at: epoch
        )
        switch consume transition {
        case .output(let output): return .success(output)
        case .suspended(let request): return .suspended(request)
        }
      } catch let error as TLS13HandshakeEngineError {
        return .failure(error)
      } catch {
        return .failure(.malformedInput)
      }
    }
  }

  private mutating func discardNextMessage(
    at level: QUICTLSHandshakeInputLevel
  ) throws(QUICTLSHandshakeError) {
    do {
      switch level {
      case .initial: try initialStream.discardNextMessage()
      case .handshake: try handshakeStream.discardNextMessage()
      }
    } catch let error {
      throw .stream(error)
    }
  }

  private static func makeStream(
    level: QUICHandshakeEncryptionLevel,
    maximumBufferedByteCount: Int,
    maximumMessageByteCount: Int
  ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeStream {
    do {
      return try QUICTLSHandshakeStream.make(
        encryptionLevel: level,
        maximumBufferedByteCount: maximumBufferedByteCount,
        maximumMessageByteCount: maximumMessageByteCount
      )
    } catch let error {
      throw .stream(error)
    }
  }
}
