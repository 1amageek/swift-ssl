import SSLCore
import SSLCrypto
import TLSTypes

/// TLS 1.3 server stream adapter backed by the record-independent core.
public struct TLS13ServerHandshake: TLS13ServerHandshaking, ~Copyable, Sendable {
  private var core: TLS13ServerHandshakeCore
  private var earlyRead: TLS13RecordProtector?
  private var earlyWrite: TLS13RecordProtector?
  private var handshakeRead: TLS13RecordProtector?
  private var handshakeWrite: TLS13RecordProtector?
  private var applicationRead: TLS13RecordProtector?
  private var applicationWrite: TLS13RecordProtector?
  private var pendingHandshakePlaintext: OwnedBytes?
  private var pendingHandshakeMessageRanges: ContiguousArray<ByteRange>
  private var pendingHandshakeMessageIndex: Int
  private var earlyDataByteCountReceived: UInt32
  private var hasFailed: Bool

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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
  }

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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
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
    echConfigurations: ECHServerConfigurationSet? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ServerHandshakeCore(
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
      echConfigurations: echConfigurations
    )
    self.init(core: core)
  }

  private init(core: consuming TLS13ServerHandshakeCore) {
    self.core = core
    earlyRead = nil
    earlyWrite = nil
    handshakeRead = nil
    handshakeWrite = nil
    applicationRead = nil
    applicationWrite = nil
    pendingHandshakePlaintext = nil
    pendingHandshakeMessageRanges = []
    pendingHandshakeMessageIndex = 0
    earlyDataByteCountReceived = 0
    hasFailed = false
  }

  public var isEstablished: Bool { !hasFailed && core.isEstablished }

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
  ) throws(TLS13HandshakeEngineError) {
    guard !hasFailed else { throw .invalidState }
    try core.configureCertificateCompression(configuration)
  }

  public mutating func receive(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    guard !hasFailed, !core.isEstablished else { throw .invalidState }
    do {
      let ranges = try TLS13HandshakeWire.recordRanges(input)
      guard !ranges.isEmpty else { throw TLS13HandshakeEngineError.malformedInput }
      var recordBytes = ContiguousArray<UInt8>()
      var actions = ContiguousArray<TLSStreamAction>()
      var outgoingRecordByteCount = 0
      var index = 0
      if handshakeRead == nil {
        let record = try inputSpan(input, range: ranges[0])
        let message = try TLS13HandshakeWire.plaintextPayload(record: record)
        try appendCoreOutput(
          try core.receiveHandshakeMessage(message, at: .initial),
          recordBytes: &recordBytes,
          terminalActions: &actions
        )
        outgoingRecordByteCount = recordBytes.count
        index = 1
      }
      while index < ranges.count {
        let record = try inputSpan(input, range: ranges[index])
        if earlyRead != nil {
          do {
            let opened = try openEarlyRecord(record)
            switch opened.contentType {
            case .applicationData:
              if core.earlyDataState == .accepted {
                let nextCount = UInt64(earlyDataByteCountReceived)
                  + UInt64(opened.plaintext.count)
                guard nextCount <= UInt64(core.earlyDataByteLimit) else {
                  throw TLS13HandshakeEngineError.malformedInput
                }
                let offset = recordBytes.count
                append(opened.plaintext.span, to: &recordBytes)
                let range = try ByteRange(
                  offset: offset,
                  count: opened.plaintext.count
                )
                actions.append(
                  .deliverApplicationData(bytes: range, isEarlyData: true)
                )
                earlyDataByteCountReceived = UInt32(nextCount)
              }
            case .handshake:
              guard core.earlyDataState == .accepted else {
                throw TLS13HandshakeEngineError.malformedInput
              }
              let messageRanges = try TLS13HandshakeWire
                .handshakeMessageRanges(opened.plaintext.span)
              guard messageRanges.count == 1 else {
                throw TLS13HandshakeEngineError.malformedInput
              }
              let message = try opened.plaintext.span(in: messageRanges[0])
              try appendCoreOutput(
                try core.receiveHandshakeMessage(message, at: .earlyData),
                recordBytes: &recordBytes,
                terminalActions: &actions
              )
              earlyRead = nil
            case .alert, .changeCipherSpec:
              throw TLS13HandshakeEngineError.malformedInput
            }
            index += 1
            continue
          } catch TLS13HandshakeEngineError.record(.authenticationFailed)
            where core.earlyDataState == .rejected
          {
            let plaintext = try openHandshakeRecord(record)
            earlyRead = nil
            try processHandshakePlaintext(
              plaintext,
              recordBytes: &recordBytes,
              terminalActions: &actions
            )
            index += 1
            continue
          }
        }
        do {
          let plaintext = try openHandshakeRecord(record)
          try processHandshakePlaintext(
            plaintext,
            recordBytes: &recordBytes,
            terminalActions: &actions
          )
        } catch TLS13HandshakeEngineError.record(.authenticationFailed)
          where core.earlyDataState == .rejected
        {
          // A rejected offer may use a ticket unknown to this server, so no
          // early key exists. TLS application-data records are ambiguous until
          // one authenticates with the handshake key; unauthenticated records
          // are discarded and never exposed as application data.
          index += 1
          continue
        } catch let error {
          throw error
        }
        index += 1
      }
      return try makeOutput(
        storage: recordBytes,
        outgoingRecordByteCount: outgoingRecordByteCount,
        actions: actions
      )
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func receiveRecordStep(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition {
    guard !hasFailed, !core.isEstablished,
      pendingHandshakePlaintext == nil
    else {
      throw .invalidState
    }
    do {
      let recordRanges = try TLS13HandshakeWire.recordRanges(input)
      guard recordRanges.count == 1 else {
        throw TLS13HandshakeEngineError.malformedInput
      }
      let record = try inputSpan(input, range: recordRanges[0])
      var recordBytes = ContiguousArray<UInt8>()
      var actions = ContiguousArray<TLSStreamAction>()
      let request: TLS13CapabilityRequest?
      if handshakeRead == nil {
        let message = try TLS13HandshakeWire.plaintextPayload(record: record)
        request = try appendCoreTransition(
          try core.receiveHandshakeMessageStep(message, at: .initial),
          recordBytes: &recordBytes,
          terminalActions: &actions
        )
      } else {
        let plaintext = try openHandshakeRecord(record)
        request = try processHandshakePlaintextStep(
          plaintext,
          startingAt: 0,
          recordBytes: &recordBytes,
          terminalActions: &actions
        )
      }
      let output = try makeOutput(
        storage: recordBytes,
        outgoingRecordByteCount: recordBytes.count,
        actions: actions
      )
      if let request {
        return .suspended(request, output)
      }
      return .output(output)
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition {
    guard !hasFailed, !core.isEstablished else { throw .invalidState }
    var recordBytes = ContiguousArray<UInt8>()
    var actions = ContiguousArray<TLSStreamAction>()
    let transition = try core.resume(response)
    if let request = try appendCoreTransition(
      transition,
      recordBytes: &recordBytes,
      terminalActions: &actions
    ) {
      return .suspended(
        request,
        try makeOutput(
          storage: recordBytes,
          outgoingRecordByteCount: recordBytes.count,
          actions: actions
        )
      )
    }
    if let plaintext = pendingHandshakePlaintext.take() {
      let startIndex = pendingHandshakeMessageIndex
      if let request = try processHandshakePlaintextStep(
        plaintext,
        startingAt: startIndex,
        recordBytes: &recordBytes,
        terminalActions: &actions
      ) {
        return .suspended(
          request,
          try makeOutput(
            storage: recordBytes,
            outgoingRecordByteCount: recordBytes.count,
            actions: actions
          )
        )
      }
    }
    return .output(
      try makeOutput(
        storage: recordBytes,
        outgoingRecordByteCount: recordBytes.count,
        actions: actions
      )
    )
  }

  public mutating func sendApplicationData(
    _ content: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    guard isEstablished, var protector = applicationWrite.take() else {
      throw .invalidState
    }
    let record: OwnedBytes
    do {
      record = try TLS13HandshakeWire.seal(
        content: content,
        contentType: .applicationData,
        with: &protector
      )
    } catch let error {
      applicationWrite = consume protector
      throw mapHandshakeEngineError(error)
    }
    applicationWrite = consume protector
    return try TLS13HandshakeWire.makeOutput(bytes: record)
  }

  /// Emits an encrypted TLS 1.3 close_notify alert.
  public mutating func sendCloseNotify()
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  {
    guard isEstablished, var protector = applicationWrite.take() else {
      throw .invalidState
    }
    let record: OwnedBytes
    do {
      record = try TLS13HandshakeWire.closeNotify(with: &protector)
    } catch let error {
      applicationWrite = consume protector
      throw error
    }
    applicationWrite = consume protector
    return try TLS13HandshakeWire.makeOutput(bytes: record)
  }

  public mutating func receiveApplicationRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    guard isEstablished else { throw .invalidState }
    do {
      return try openSingleApplicationRecord(input)
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func receiveApplicationRecordStep(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13StreamRecordTransition {
    guard !hasFailed, isEstablished else { throw .invalidState }
    do {
      let opened = try openSingleEncryptedRecord(input)
      switch opened.contentType {
      case .applicationData:
        return .applicationData(opened.plaintext)
      case .handshake:
        return .postHandshake(
          try processPostHandshakePlaintextStep(opened.plaintext)
        )
      case .alert:
        return .alert(try TLS13HandshakeWire.parseAlert(opened.plaintext))
      case .changeCipherSpec:
        throw TLS13HandshakeEngineError.malformedInput
      }
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func sendNewSessionTicket(
    lifetime: UInt32,
    ageAdd: UInt32,
    ticketNonce: Span<UInt8>,
    ticket: Span<UInt8>,
    issuedAt: VerificationInstant,
    maximumEarlyDataByteCount: UInt32 = 0,
    extensions: Span<UInt8> = Span<UInt8>()
  ) throws(TLS13HandshakeEngineError) -> TLS13IssuedSessionTicket {
    guard isEstablished, var protector = applicationWrite.take() else {
      throw .invalidState
    }
    do {
      let message = try TLS13SessionTicketCodec.makeNewSessionTicket(
        lifetime: lifetime,
        ageAdd: ageAdd,
        ticketNonce: ticketNonce,
        ticket: ticket,
        maximumEarlyDataByteCount: maximumEarlyDataByteCount,
        extensions: extensions
      )
      let resumptionState = try core.makeResumptionState(
        ticket: ticket,
        ticketNonce: ticketNonce,
        issuedAt: issuedAt,
        lifetime: lifetime,
        ageAdd: ageAdd,
        maximumEarlyDataByteCount: maximumEarlyDataByteCount
      )
      let record = try TLS13HandshakeWire.seal(
        content: message.span,
        contentType: .handshake,
        with: &protector
      )
      let output = try TLS13HandshakeWire.makeOutput(bytes: record)
      applicationWrite = consume protector
      return TLS13IssuedSessionTicket(
        output: output,
        resumptionState: resumptionState
      )
    } catch let error {
      applicationWrite = consume protector
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func requestKeyUpdate(
    requestPeerUpdate: Bool = false
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    try makeKeyUpdate(
      endpoint: .server,
      requestPeerUpdate: requestPeerUpdate
    )
  }

  public mutating func requestPostHandshakeClientAuthentication(
    requestContext: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    guard !hasFailed, isEstablished else { throw .invalidState }
    var recordBytes = ContiguousArray<UInt8>()
    var actions = ContiguousArray<TLSStreamAction>()
    try appendCoreOutput(
      try core.requestPostHandshakeClientAuthentication(
        requestContext: requestContext
      ),
      recordBytes: &recordBytes,
      terminalActions: &actions
    )
    return try makeOutput(
      storage: recordBytes,
      outgoingRecordByteCount: recordBytes.count,
      actions: actions
    )
  }

  public mutating func receivePostHandshakeRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    let transition = try receivePostHandshakeRecordStep(input)
    switch consume transition {
    case .output(let output):
      return output
    case .suspended:
      throw .capability(.wrongState)
    }
  }

  public mutating func receivePostHandshakeRecordStep(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition {
    guard !hasFailed, isEstablished else { throw .invalidState }
    do {
      let plaintext = try openHandshakeApplicationRecord(input)
      return try processPostHandshakePlaintextStep(plaintext)
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  private mutating func processPostHandshakePlaintextStep(
    _ plaintext: borrowing OwnedBytes
  ) throws(TLS13HandshakeEngineError) -> TLS13StreamHandshakeTransition {
    do {
      let ranges = try TLS13HandshakeWire.handshakeMessageRanges(plaintext.span)
      guard ranges.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
      let message = try plaintext.span(in: ranges[0])
      if !message.isEmpty, message[0] == TLS13HandshakeCodec.keyUpdateType {
        let requestPeerUpdate = try TLS13HandshakeCodec.parseKeyUpdate(message)
        let secret = try core.updateApplicationTrafficSecret(for: .client)
        applicationRead = try makeProtector(secret)
        let output = requestPeerUpdate
          ? try requestKeyUpdate(requestPeerUpdate: false)
          : try TLS13HandshakeWire.makeOutput(bytes: OwnedBytes())
        return .output(output)
      }
      var recordBytes = ContiguousArray<UInt8>()
      var actions = ContiguousArray<TLSStreamAction>()
      let request = try appendCoreTransition(
        try core.receiveHandshakeMessageStep(message, at: .application),
        recordBytes: &recordBytes,
        terminalActions: &actions
      )
      let output = try makeOutput(
        storage: recordBytes,
        outgoingRecordByteCount: recordBytes.count,
        actions: actions
      )
      if let request { return .suspended(request, output) }
      return .output(output)
    } catch let error {
      throw mapHandshakeEngineError(error)
    }
  }

  private mutating func appendCoreOutput(
    _ output: consuming TLS13HandshakeCoreOutput,
    recordBytes: inout ContiguousArray<UInt8>,
    terminalActions: inout ContiguousArray<TLSStreamAction>
  ) throws(TLS13HandshakeEngineError) {
    try TLS13StreamCoreOutputAdapter.append(
      output,
      role: .server,
      recordBytes: &recordBytes,
      terminalActions: &terminalActions,
      earlyRead: &earlyRead,
      earlyWrite: &earlyWrite,
      handshakeRead: &handshakeRead,
      handshakeWrite: &handshakeWrite,
      applicationRead: &applicationRead,
      applicationWrite: &applicationWrite
    )
  }

  private mutating func appendCoreTransition(
    _ transition: consuming TLS13HandshakeCoreTransition,
    recordBytes: inout ContiguousArray<UInt8>,
    terminalActions: inout ContiguousArray<TLSStreamAction>
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest? {
    switch consume transition {
    case .output(let output):
      try appendCoreOutput(
        output,
        recordBytes: &recordBytes,
        terminalActions: &terminalActions
      )
      return nil
    case .suspended(let request):
      return request
    }
  }

  private mutating func processHandshakePlaintextStep(
    _ plaintext: consuming OwnedBytes,
    startingAt startIndex: Int,
    recordBytes: inout ContiguousArray<UInt8>,
    terminalActions: inout ContiguousArray<TLSStreamAction>
  ) throws(TLS13HandshakeEngineError) -> TLS13CapabilityRequest? {
    let ranges: ContiguousArray<ByteRange>
    if startIndex == 0 {
      ranges = try TLS13HandshakeWire.handshakeMessageRanges(plaintext.span)
    } else {
      ranges = pendingHandshakeMessageRanges
    }
    pendingHandshakeMessageRanges = []
    pendingHandshakeMessageIndex = 0
    var index = startIndex
    while index < ranges.count {
      let message: Span<UInt8>
      do {
        message = try plaintext.span(in: ranges[index])
      } catch let error {
        throw .output(error)
      }
      let transition = try core.receiveHandshakeMessageStep(
        message,
        at: .handshake
      )
      index += 1
      if let request = try appendCoreTransition(
        transition,
        recordBytes: &recordBytes,
        terminalActions: &terminalActions
      ) {
        if index < ranges.count {
          pendingHandshakePlaintext = plaintext
          pendingHandshakeMessageRanges = ranges
          pendingHandshakeMessageIndex = index
        }
        return request
      }
    }
    pendingHandshakePlaintext = nil
    return nil
  }

  private mutating func openHandshakeRecord(
    _ record: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    guard var protector = handshakeRead.take() else { throw .invalidState }
    do {
      let plaintext = try TLS13HandshakeWire.open(
        record: record,
        with: &protector
      )
      handshakeRead = consume protector
      return plaintext
    } catch let error {
      handshakeRead = consume protector
      throw error
    }
  }

  private mutating func openEarlyRecord(
    _ record: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> (
    contentType: TLS13ContentType,
    plaintext: OwnedBytes
  ) {
    guard var protector = earlyRead.take() else { throw .invalidState }
    let innerByteCount = Swift.max(
      0,
      record.count - TLS13RecordProtector.recordHeaderByteCount - 16
    )
    var plaintext = ContiguousArray<UInt8>(
      repeating: 0,
      count: innerByteCount
    )
    var destination = plaintext.mutableSpan
    do {
      let contentType = try protector.open(
        record: record,
        into: &destination
      )
      let unusedByteCount = plaintext.count - protector.lastOpenedByteCount
      if unusedByteCount > 0 { plaintext.removeLast(unusedByteCount) }
      earlyRead = consume protector
      return (contentType, OwnedBytes(consuming: plaintext))
    } catch let error {
      earlyRead = consume protector
      throw .record(error)
    }
  }

  private mutating func processHandshakePlaintext(
    _ plaintext: borrowing OwnedBytes,
    recordBytes: inout ContiguousArray<UInt8>,
    terminalActions: inout ContiguousArray<TLSStreamAction>
  ) throws(TLS13HandshakeEngineError) {
    let messageRanges = try TLS13HandshakeWire.handshakeMessageRanges(
      plaintext.span
    )
    for messageRange in messageRanges {
      let message: Span<UInt8>
      do {
        message = try plaintext.span(in: messageRange)
      } catch let error {
        throw .output(error)
      }
      try appendCoreOutput(
        try core.receiveHandshakeMessage(message, at: .handshake),
        recordBytes: &recordBytes,
        terminalActions: &terminalActions
      )
    }
  }

  private func makeOutput(
    storage: consuming ContiguousArray<UInt8>,
    outgoingRecordByteCount: Int,
    actions terminalActions: consuming ContiguousArray<TLSStreamAction>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    var actions = ContiguousArray<TLSStreamAction>()
    if outgoingRecordByteCount > 0 {
      let range: ByteRange
      do {
        range = try ByteRange(offset: 0, count: outgoingRecordByteCount)
      } catch let error {
        throw .output(error)
      }
      actions.append(
        .emitRecordBytes(range)
      )
    }
    actions.append(contentsOf: terminalActions)
    return try TLS13HandshakeOutput(
      bytes: OwnedBytes(consuming: storage),
      actions: actions
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

  private mutating func openHandshakeApplicationRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    try openSingleEncryptedRecord(input).plaintext
  }

  private mutating func openSingleApplicationRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    let opened = try openSingleEncryptedRecord(input)
    guard opened.contentType == .applicationData else {
      throw TLS13HandshakeEngineError.malformedInput
    }
    return opened.plaintext
  }

  private mutating func openSingleEncryptedRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> (
    contentType: TLS13ContentType,
    plaintext: OwnedBytes
  ) {
    let ranges = try TLS13HandshakeWire.recordRanges(input)
    guard ranges.count == 1,
      var protector = applicationRead.take()
    else {
      throw .malformedInput
    }
    do {
      let result = try TLS13HandshakeWire.openAny(
        record: try inputSpan(input, range: ranges[0]),
        with: &protector
      )
      applicationRead = consume protector
      return result
    } catch let error {
      applicationRead = consume protector
      throw mapHandshakeEngineError(error)
    }
  }

  private mutating func makeKeyUpdate(
    endpoint: TLSRole,
    requestPeerUpdate: Bool
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    guard isEstablished, var protector = applicationWrite.take() else {
      throw .invalidState
    }
    let record: OwnedBytes
    do {
      let message = try TLS13HandshakeCodec.makeKeyUpdate(
        requestUpdate: requestPeerUpdate
      )
      record = try TLS13HandshakeWire.seal(
        content: message.span,
        contentType: .handshake,
        with: &protector
      )
    } catch let error {
      applicationWrite = consume protector
      throw mapHandshakeEngineError(error)
    }
    do {
      let secret = try core.updateApplicationTrafficSecret(for: endpoint)
      applicationWrite = try makeProtector(secret)
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
    return try TLS13HandshakeWire.makeOutput(bytes: record)
  }

  private func makeProtector(
    _ secret: borrowing TLS13TrafficSecret
  ) throws(TLS13HandshakeEngineError) -> TLS13RecordProtector {
    do {
      return try secret.withBorrowedSecret { bytes throws(TLS13RecordError) in
        try TLS13RecordProtector(
          cipherSuite: secret.cipherSuite,
          trafficSecret: bytes
        )
      }
    } catch let error {
      throw .record(error)
    }
  }

  private func inputSpan(
    _ input: Span<UInt8>,
    range: ByteRange
  ) throws(TLS13HandshakeEngineError) -> Span<UInt8> {
    guard range.endOffset <= input.count else { throw .malformedInput }
    return input.extracting(range.offset..<range.endOffset)
  }
}
import TLSTypes
