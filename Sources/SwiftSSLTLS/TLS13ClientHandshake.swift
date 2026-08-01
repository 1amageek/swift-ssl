import SwiftSSLCore
import SwiftSSLCrypto

/// TLS 1.3 client stream adapter backed by the record-independent core.
public struct TLS13ClientHandshake: TLS13ClientHandshaking, ~Copyable, Sendable {
  private var core: TLS13ClientHandshakeCore
  private var handshakeRead: TLS13RecordProtector?
  private var handshakeWrite: TLS13RecordProtector?
  private var applicationRead: TLS13RecordProtector?
  private var applicationWrite: TLS13RecordProtector?
  private var hasFailed: Bool

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
    let core = try TLS13ClientHandshakeCore(
      random: random,
      ephemeralKey: ephemeralKey,
      expectedServerPublicKey: expectedServerPublicKey,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: resumptionState,
      echConfiguration: consume echConfiguration
    )
    self.init(core: core)
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
    let core = try TLS13ClientHandshakeCore(
      random: random,
      keyExchange: keyExchange,
      expectedServerPublicKey: expectedServerPublicKey,
      serverName: serverName,
      verificationInstant: verificationInstant,
      cipherSuite: cipherSuite,
      resumptionState: resumptionState,
      echConfiguration: consume echConfiguration
    )
    self.init(core: core)
  }

  private init(core: consuming TLS13ClientHandshakeCore) {
    self.core = core
    handshakeRead = nil
    handshakeWrite = nil
    applicationRead = nil
    applicationWrite = nil
    hasFailed = false
  }

  public var isEstablished: Bool { !hasFailed && core.isEstablished }

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
    guard isEstablished else { throw .invalidState }
    do {
      let message = try openHandshakeApplicationRecord(input)
      let ranges = try TLS13HandshakeWire.handshakeMessageRanges(message.span)
      guard ranges.count == 1 else { throw TLS13HandshakeEngineError.malformedInput }
      let requestPeerUpdate = try TLS13HandshakeCodec.parseKeyUpdate(
        try message.span(in: ranges[0])
      )
      let secret = try core.updateApplicationTrafficSecret(for: .server)
      applicationRead = try makeProtector(secret)
      if requestPeerUpdate {
        return try requestKeyUpdate(requestPeerUpdate: false)
      }
      return try TLS13HandshakeWire.makeOutput(bytes: OwnedBytes())
    } catch let error {
      hasFailed = true
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
      handshakeRead: &handshakeRead,
      handshakeWrite: &handshakeWrite,
      applicationRead: &applicationRead,
      applicationWrite: &applicationWrite
    )
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
    let ranges = try TLS13HandshakeWire.recordRanges(input)
    guard ranges.count == 1,
      var protector = applicationRead.take()
    else {
      throw .malformedInput
    }
    do {
      let plaintext = try TLS13HandshakeWire.open(
        record: try inputSpan(input, range: ranges[0]),
        with: &protector
      )
      applicationRead = consume protector
      return plaintext
    } catch let error {
      applicationRead = consume protector
      throw error
    }
  }

  private mutating func openSingleApplicationRecord(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    let ranges = try TLS13HandshakeWire.recordRanges(input)
    guard ranges.count == 1,
      var protector = applicationRead.take()
    else {
      throw .malformedInput
    }
    do {
      let result = try TLS13HandshakeWire.open(
        record: try inputSpan(input, range: ranges[0]),
        expectedContentType: .applicationData,
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
