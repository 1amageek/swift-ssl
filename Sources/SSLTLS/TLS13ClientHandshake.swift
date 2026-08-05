import SSLCore
import SSLCrypto
import TLSTypes

/// TLS 1.3 client stream adapter backed by the record-independent core.
public struct TLS13ClientHandshake: TLS13ClientHandshaking, ~Copyable, Sendable {
  private var core: TLS13ClientHandshakeCore
  private var earlyRead: TLS13RecordProtector?
  private var earlyWrite: TLS13RecordProtector?
  private var handshakeRead: TLS13RecordProtector?
  private var handshakeWrite: TLS13RecordProtector?
  private var applicationRead: TLS13RecordProtector?
  private var applicationWrite: TLS13RecordProtector?
  private var pendingHandshakePlaintext: OwnedBytes?
  private var pendingHandshakeMessageRanges: ContiguousArray<ByteRange>
  private var pendingHandshakeMessageIndex: Int
  private var earlyDataByteCountSent: UInt32
  private var hasFailed: Bool
  private let verificationInstant: VerificationInstant

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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
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
    echConfiguration: consuming ECHClientConfiguration? = nil
  ) throws(TLS13HandshakeEngineError) {
    let core = try TLS13ClientHandshakeCore(
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
      echConfiguration: consume echConfiguration
    )
    self.init(core: core, verificationInstant: verificationInstant)
  }

  private init(
    core: consuming TLS13ClientHandshakeCore,
    verificationInstant: VerificationInstant
  ) {
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
    earlyDataByteCountSent = 0
    hasFailed = false
    self.verificationInstant = verificationInstant
  }

  public var isEstablished: Bool { !hasFailed && core.isEstablished }

  public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
    core.negotiatedApplicationProtocol
  }

  public var receivedTransportParameters: OwnedBytes? {
    core.receivedTransportParameters
  }

  public var earlyDataState: TLS13EarlyDataState { core.earlyDataState }

  public var earlyDataByteLimit: UInt32 { core.earlyDataByteLimit }

  public mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(TLS13HandshakeEngineError) {
    guard !hasFailed else { throw .invalidState }
    try core.configureCertificateCompression(configuration)
  }

  public mutating func start()
    throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput
  {
    guard !hasFailed else { throw .invalidState }
    do {
      var recordBytes = ContiguousArray<UInt8>()
      var actions = ContiguousArray<TLSStreamAction>()
      try appendCoreOutput(
        try core.start(),
        recordBytes: &recordBytes,
        terminalActions: &actions
      )
      return try TLS13HandshakeWire.makeOutput(
        storage: recordBytes,
        terminalActions: actions
      )
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
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
      var index = 0
      if handshakeRead == nil {
        let record = try inputSpan(input, range: ranges[0])
        let message = try TLS13HandshakeWire.plaintextPayload(record: record)
        try appendCoreOutput(
          try core.receiveHandshakeMessage(message, at: .initial),
          recordBytes: &recordBytes,
          terminalActions: &actions
        )
        index = 1
      }
      while index < ranges.count {
        let record = try inputSpan(input, range: ranges[index])
        let plaintext = try openHandshakeRecord(record)
        let messageRanges = try TLS13HandshakeWire.handshakeMessageRanges(
          plaintext.span
        )
        for messageRange in messageRanges {
          let message = try plaintext.span(in: messageRange)
          try appendCoreOutput(
            try core.receiveHandshakeMessage(message, at: .handshake),
            recordBytes: &recordBytes,
            terminalActions: &actions
          )
        }
        index += 1
      }
      return try TLS13HandshakeWire.makeOutput(
        storage: recordBytes,
        terminalActions: actions
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
      let output = try TLS13HandshakeWire.makeOutput(
        storage: recordBytes,
        terminalActions: actions
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
        try TLS13HandshakeWire.makeOutput(
          storage: recordBytes,
          terminalActions: actions
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
          try TLS13HandshakeWire.makeOutput(
            storage: recordBytes,
            terminalActions: actions
          )
        )
      }
    }
    return .output(
      try TLS13HandshakeWire.makeOutput(
        storage: recordBytes,
        terminalActions: actions
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

  public mutating func sendEarlyData(
    _ content: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    guard !hasFailed,
      core.earlyDataState == .offered,
      var protector = earlyWrite.take()
    else {
      throw .invalidState
    }
    let nextCount = UInt64(earlyDataByteCountSent) + UInt64(content.count)
    guard nextCount <= UInt64(core.earlyDataByteLimit) else {
      earlyWrite = consume protector
      throw .invalidConfiguration
    }
    let record: OwnedBytes
    do {
      record = try TLS13HandshakeWire.seal(
        content: content,
        contentType: .applicationData,
        with: &protector
      )
    } catch let error {
      earlyWrite = consume protector
      throw mapHandshakeEngineError(error)
    }
    earlyWrite = consume protector
    earlyDataByteCountSent = UInt32(nextCount)
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
        let messageRanges = try TLS13HandshakeWire.handshakeMessageRanges(
          opened.plaintext.span
        )
        guard messageRanges.count == 1 else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        let message = try opened.plaintext.span(in: messageRanges[0])
        if !message.isEmpty,
          message[0] == TLS13SessionTicketCodec.newSessionTicketType
        {
          let ticket = try TLS13SessionTicketCodec.parseNewSessionTicket(message)
          return .sessionTicket(
            try core.makeResumptionState(
              ticket: ticket,
              receivedAt: verificationInstant
            )
          )
        }
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

  public mutating func receiveNewSessionTicket(
    _ input: Span<UInt8>,
    receivedAt: VerificationInstant
  ) throws(TLS13HandshakeEngineError) -> TLS13ResumptionState {
    guard isEstablished else { throw .invalidState }
    do {
      let message = try openHandshakeApplicationRecord(input)
      let ranges = try TLS13HandshakeWire.handshakeMessageRanges(message.span)
      guard ranges.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
      let ticket = try TLS13SessionTicketCodec.parseNewSessionTicket(
        try message.span(in: ranges[0])
      )
      return try core.makeResumptionState(
        ticket: ticket,
        receivedAt: receivedAt
      )
    } catch let error {
      hasFailed = true
      throw mapHandshakeEngineError(error)
    }
  }

  public mutating func requestKeyUpdate(
    requestPeerUpdate: Bool = false
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    try makeKeyUpdate(
      endpoint: .client,
      requestPeerUpdate: requestPeerUpdate
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
        let secret = try core.updateApplicationTrafficSecret(for: .server)
        applicationRead = try makeProtector(secret)
        let output = requestPeerUpdate
          ? try requestKeyUpdate(requestPeerUpdate: false)
          : try TLS13HandshakeWire.makeOutput(bytes: OwnedBytes())
        return .output(output)
      }
      var recordBytes = ContiguousArray<UInt8>()
      var actions = ContiguousArray<TLSStreamAction>()
      let request = try appendCoreTransition(
        try core.receivePostHandshakeAuthenticationRequestStep(message),
        recordBytes: &recordBytes,
        terminalActions: &actions
      )
      let output = try TLS13HandshakeWire.makeOutput(
        storage: recordBytes,
        terminalActions: actions
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
      role: .client,
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
