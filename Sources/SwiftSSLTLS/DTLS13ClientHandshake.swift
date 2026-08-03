import SwiftSSLCore
import SwiftSSLCrypto

/// Deterministic DTLS 1.3 client composed from the shared TLS semantic core.
public struct DTLS13ClientHandshake: DTLS13ClientHandshaking, ~Copyable, Sendable {
  private var core: TLS13ClientHandshakeCore
  private var reassembler: RFC9147DTLS13HandshakeReassembler
  private var flightController: RFC9147DTLS13FlightController
  private var initialReplayWindow: DTLS13ReplayWindow
  private var handshakeRead: RFC9147DTLS13RecordProtector?
  private var handshakeWrite: RFC9147DTLS13RecordProtector?
  private var applicationRead: RFC9147DTLS13RecordProtector?
  private var applicationWrite: RFC9147DTLS13RecordProtector?
  private var previousApplicationRead: RFC9147DTLS13RecordProtector?
  private var pendingApplicationWrite: RFC9147DTLS13RecordProtector?
  private var acknowledgedHandshakeRecordNumbers: Set<DTLS13RecordNumber>
  private var shouldRespondToKeyUpdate: Bool
  private var pendingCapabilityDatagram: OwnedBytes?
  private var pendingCapabilityEpoch: TLS13HandshakeEpoch?
  private let localConnectionID: OwnedBytes
  private let peerConnectionID: OwnedBytes
  private let maximumDatagramByteCount: Int
  private var nextMessageSequence: UInt32
  private var nextInitialRecordSequence: UInt64
  public private(set) var isHandshakeConfirmed: Bool

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    certificateValidator: any TLS13ServerCertificateValidating,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        certificateValidator: certificateValidator,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ClientKeyExchange,
    externalServerTrust: TLS13ExternalServerTrust,
    clientIdentity: consuming TLS13ClientIdentity? = nil,
    externalClientCredential: TLS13ExternalClientCredential? = nil,
    applicationProtocols: ContiguousArray<TLS13ApplicationProtocol> = [],
    serverName: Span<UInt8>? = nil,
    verificationInstant: VerificationInstant,
    cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
    srtpConfiguration: DTLSSRTPClientConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ClientHandshakeCore
    do {
      core = try TLS13ClientHandshakeCore(
        random: random,
        keyExchange: keyExchange,
        externalServerTrust: externalServerTrust,
        clientIdentity: consume clientIdentity,
        externalClientCredential: externalClientCredential,
        applicationProtocols: applicationProtocols,
        serverName: serverName,
        verificationInstant: verificationInstant,
        cipherSuite: cipherSuite,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  private static func make(
    core: consuming TLS13ClientHandshakeCore,
    srtpConfiguration: DTLSSRTPClientConfiguration?,
    localConnectionID: Span<UInt8>?,
    peerConnectionID: Span<UInt8>?,
    maximumDatagramByteCount: Int
  ) throws(DTLS13ConnectionError) -> Self {
    guard maximumDatagramByteCount >= 256 else {
      throw .invalidConfiguration
    }
    let reassembler: RFC9147DTLS13HandshakeReassembler
    let flightController: RFC9147DTLS13FlightController
    do {
      reassembler = try RFC9147DTLS13HandshakeReassembler()
      flightController = try RFC9147DTLS13FlightController()
    } catch let error as DTLS13HandshakeFragmentError {
      throw .fragment(error)
    } catch let error as DTLS13FlightError {
      throw .flight(error)
    } catch {
      throw .invalidConfiguration
    }
    let ownedLocalConnectionID: OwnedBytes
    if let localConnectionID {
      ownedLocalConnectionID = OwnedBytes(copying: localConnectionID)
    } else {
      ownedLocalConnectionID = OwnedBytes()
    }
    let ownedPeerConnectionID: OwnedBytes
    if let peerConnectionID {
      ownedPeerConnectionID = OwnedBytes(copying: peerConnectionID)
    } else {
      ownedPeerConnectionID = OwnedBytes()
    }
    var configuredCore = consume core
    do {
      try configuredCore.configureDTLSConnectionIDs(
        local: ownedLocalConnectionID,
        expectedPeer: ownedPeerConnectionID
      )
      if let srtpConfiguration {
        try configuredCore.configureDTLSSRTP(srtpConfiguration)
      }
    } catch let error {
      throw .handshake(error)
    }
    return Self(
      core: configuredCore,
      reassembler: reassembler,
      flightController: flightController,
      initialReplayWindow: DTLS13ReplayWindow(),
      handshakeRead: nil,
      handshakeWrite: nil,
      applicationRead: nil,
      applicationWrite: nil,
      previousApplicationRead: nil,
      pendingApplicationWrite: nil,
      acknowledgedHandshakeRecordNumbers: [],
      shouldRespondToKeyUpdate: false,
      pendingCapabilityDatagram: nil,
      pendingCapabilityEpoch: nil,
      localConnectionID: ownedLocalConnectionID,
      peerConnectionID: ownedPeerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount,
      nextMessageSequence: 0,
      nextInitialRecordSequence: 0,
      isHandshakeConfirmed: false
    )
  }

  private init(
    core: consuming TLS13ClientHandshakeCore,
    reassembler: consuming RFC9147DTLS13HandshakeReassembler,
    flightController: consuming RFC9147DTLS13FlightController,
    initialReplayWindow: DTLS13ReplayWindow,
    handshakeRead: consuming RFC9147DTLS13RecordProtector?,
    handshakeWrite: consuming RFC9147DTLS13RecordProtector?,
    applicationRead: consuming RFC9147DTLS13RecordProtector?,
    applicationWrite: consuming RFC9147DTLS13RecordProtector?,
    previousApplicationRead: consuming RFC9147DTLS13RecordProtector?,
    pendingApplicationWrite: consuming RFC9147DTLS13RecordProtector?,
    acknowledgedHandshakeRecordNumbers: consuming Set<DTLS13RecordNumber>,
    shouldRespondToKeyUpdate: Bool,
    pendingCapabilityDatagram: consuming OwnedBytes?,
    pendingCapabilityEpoch: TLS13HandshakeEpoch?,
    localConnectionID: consuming OwnedBytes,
    peerConnectionID: consuming OwnedBytes,
    maximumDatagramByteCount: Int,
    nextMessageSequence: UInt32,
    nextInitialRecordSequence: UInt64,
    isHandshakeConfirmed: Bool
  ) {
    self.core = core
    self.reassembler = reassembler
    self.flightController = flightController
    self.initialReplayWindow = initialReplayWindow
    self.handshakeRead = handshakeRead
    self.handshakeWrite = handshakeWrite
    self.applicationRead = applicationRead
    self.applicationWrite = applicationWrite
    self.previousApplicationRead = previousApplicationRead
    self.pendingApplicationWrite = pendingApplicationWrite
    self.acknowledgedHandshakeRecordNumbers = acknowledgedHandshakeRecordNumbers
    self.shouldRespondToKeyUpdate = shouldRespondToKeyUpdate
    self.pendingCapabilityDatagram = pendingCapabilityDatagram
    self.pendingCapabilityEpoch = pendingCapabilityEpoch
    self.localConnectionID = localConnectionID
    self.peerConnectionID = peerConnectionID
    self.maximumDatagramByteCount = maximumDatagramByteCount
    self.nextMessageSequence = nextMessageSequence
    self.nextInitialRecordSequence = nextInitialRecordSequence
    self.isHandshakeConfirmed = isHandshakeConfirmed
  }

  public var isEstablished: Bool { core.isEstablished }

  public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
    core.negotiatedApplicationProtocol
  }

  public var receivedTransportParameters: OwnedBytes? {
    core.receivedTransportParameters
  }

  public var srtpProtectionProfile: DTLSSRTPProtectionProfile? {
    core.srtpProtectionProfile
  }

  public var srtpMasterKeyIdentifier: OwnedBytes? {
    core.srtpMasterKeyIdentifier
  }

  public mutating func configureCertificateCompression(
    _ configuration: TLS13CertificateCompressionConfiguration
  ) throws(DTLS13ConnectionError) {
    do {
      try core.configureCertificateCompression(configuration)
    } catch let error {
      throw .handshake(error)
    }
  }

  public mutating func exportSRTPKeyingMaterial()
    throws(DTLS13ConnectionError) -> DTLSSRTPKeyingMaterial
  {
    do {
      return try core.exportDTLSSRTPKeyingMaterial()
    } catch let error {
      throw .handshake(error)
    }
  }

  public mutating func start() throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let coreOutput: TLS13HandshakeCoreOutput
    do {
      coreOutput = try core.start()
    } catch let error {
      throw .handshake(error)
    }
    return try transmit(coreOutput)
  }

  public mutating func receiveDatagram(
    _ datagram: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let records: ContiguousArray<DTLS13DatagramRecord>
    do {
      records = try RFC9147DTLS13DatagramRecordFramer(
        expectedConnectionIDByteCount: localConnectionID.count
      ).records(in: datagram)
    } catch let error {
      throw .record(error)
    }
    var result = try DTLSActionBatchCombiner.empty()
    var handshakeRecordNumbersToAcknowledge =
      ContiguousArray<DTLS13RecordNumber>()
    var implicitlyAcknowledged = false
    for record in records {
      let recordBytes = datagram.extracting(
        record.bytes.offset..<record.bytes.endOffset
      )
      switch record.kind {
      case .plaintext(let contentType):
        guard contentType == .handshake else {
          throw .malformedDatagram
        }
        let parsed: DTLS13PlaintextRecord
        do {
          parsed = try RFC9147DTLS13PlaintextRecordCodec()
            .records(in: recordBytes)[0]
          let decision = try initialReplayWindow.accept(
            parsed.recordNumber.sequenceNumber
          )
          guard decision == .accepted else { continue }
        } catch let error as DTLS13RecordError {
          throw .record(error)
        } catch {
          throw .malformedDatagram
        }
        if !implicitlyAcknowledged, flightController.hasOutstandingFlight {
          result = try DTLSActionBatchCombiner.appending(
            mapFlight { try $0.receiveImplicitAcknowledgment() },
            to: result
          )
          implicitlyAcknowledged = true
        }
        let content = recordBytes.extracting(
          parsed.fragment.offset..<parsed.fragment.endOffset
        )
        result = try DTLSActionBatchCombiner.appending(
          try processHandshakeContent(content, at: .initial),
          to: result
        )
      case .ciphertext(let epochBits):
        do {
          let opened = try openProtectedRecord(
            recordBytes,
            epochBits: epochBits
          )
          try processOpenedRecord(
            opened,
            result: &result,
            implicitlyAcknowledged: &implicitlyAcknowledged,
            handshakeRecordNumbersToAcknowledge:
              &handshakeRecordNumbersToAcknowledge
          )
        } catch let error as DTLS13ConnectionError {
          if case .record(.replayed(let recordNumber)) = error {
            if acknowledgedHandshakeRecordNumbers.contains(recordNumber) {
              handshakeRecordNumbersToAcknowledge.append(recordNumber)
            }
            continue
          }
          throw error
        }
      }
    }
    if !handshakeRecordNumbersToAcknowledge.isEmpty {
      result = try DTLSActionBatchCombiner.appending(
        try makeAcknowledgment(
          recordNumbers: uniqueSorted(handshakeRecordNumbersToAcknowledge)
        ),
        to: result
      )
    }
    return result
  }

  public mutating func receiveDatagramStep(
    _ datagram: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    guard pendingCapabilityDatagram == nil,
      pendingCapabilityEpoch == nil
    else {
      throw .invalidState
    }
    return try receiveDatagramStepInternal(datagram)
  }

  public mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    guard let epoch = pendingCapabilityEpoch else {
      throw .invalidState
    }
    var result = try DTLSActionBatchCombiner.empty()
    let coreTransition: TLS13HandshakeCoreTransition
    do {
      coreTransition = try core.resume(response)
    } catch let error {
      throw .handshake(error)
    }
    switch consume coreTransition {
    case .output(let output):
      result = try DTLSActionBatchCombiner.appending(
        try transmit(output),
        to: result
      )
    case .suspended(let request):
      return .suspended(request, result)
    }
    pendingCapabilityEpoch = nil
    if let request = try drainHandshakeMessagesStep(
      at: epoch,
      result: &result
    ) {
      return .suspended(request, result)
    }
    guard let remainder = pendingCapabilityDatagram.take() else {
      return .output(result)
    }
    let remainderTransition = try receiveDatagramStepInternal(remainder.span)
    switch consume remainderTransition {
    case .output(let output):
      return .output(
        try DTLSActionBatchCombiner.appending(output, to: result)
      )
    case .suspended(let request, let output):
      return .suspended(
        request,
        try DTLSActionBatchCombiner.appending(output, to: result)
      )
    }
  }

  private mutating func receiveDatagramStepInternal(
    _ datagram: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    let records: ContiguousArray<DTLS13DatagramRecord>
    do {
      records = try RFC9147DTLS13DatagramRecordFramer(
        expectedConnectionIDByteCount: localConnectionID.count
      ).records(in: datagram)
    } catch let error {
      throw .record(error)
    }
    var result = try DTLSActionBatchCombiner.empty()
    var recordNumbersToAcknowledge = ContiguousArray<DTLS13RecordNumber>()
    var implicitlyAcknowledged = false
    for record in records {
      let recordBytes = datagram.extracting(
        record.bytes.offset..<record.bytes.endOffset
      )
      let request: TLS13CapabilityRequest?
      switch record.kind {
      case .plaintext(let contentType):
        guard contentType == .handshake else {
          throw .malformedDatagram
        }
        let parsed: DTLS13PlaintextRecord
        do {
          parsed = try RFC9147DTLS13PlaintextRecordCodec()
            .records(in: recordBytes)[0]
          let decision = try initialReplayWindow.accept(
            parsed.recordNumber.sequenceNumber
          )
          guard decision == .accepted else { continue }
        } catch let error as DTLS13RecordError {
          throw .record(error)
        } catch {
          throw .malformedDatagram
        }
        if !implicitlyAcknowledged, flightController.hasOutstandingFlight {
          result = try DTLSActionBatchCombiner.appending(
            mapFlight { try $0.receiveImplicitAcknowledgment() },
            to: result
          )
          implicitlyAcknowledged = true
        }
        let content = recordBytes.extracting(
          parsed.fragment.offset..<parsed.fragment.endOffset
        )
        request = try processHandshakeContentStep(
          content,
          at: .initial,
          result: &result
        )
      case .ciphertext(let epochBits):
        do {
          let opened = try openProtectedRecord(
            recordBytes,
            epochBits: epochBits
          )
          request = try processOpenedRecordStep(
            opened,
            result: &result,
            implicitlyAcknowledged: &implicitlyAcknowledged,
            handshakeRecordNumbersToAcknowledge: &recordNumbersToAcknowledge
          )
        } catch let error as DTLS13ConnectionError {
          if case .record(.replayed(let recordNumber)) = error {
            if acknowledgedHandshakeRecordNumbers.contains(recordNumber) {
              recordNumbersToAcknowledge.append(recordNumber)
            }
            continue
          }
          throw error
        }
      }
      if let request {
        if record.bytes.endOffset < datagram.count {
          // Suspension crosses the caller's borrow. Only the unprocessed
          // suffix is copied so its owner survives until the matching resume.
          pendingCapabilityDatagram = OwnedBytes(
            copying: datagram.extracting(record.bytes.endOffset..<datagram.count)
          )
        }
        if !recordNumbersToAcknowledge.isEmpty {
          result = try DTLSActionBatchCombiner.appending(
            try makeAcknowledgment(
              recordNumbers: uniqueSorted(recordNumbersToAcknowledge)
            ),
            to: result
          )
        }
        return .suspended(request, result)
      }
    }
    if !recordNumbersToAcknowledge.isEmpty {
      result = try DTLSActionBatchCombiner.appending(
        try makeAcknowledgment(
          recordNumbers: uniqueSorted(recordNumbersToAcknowledge)
        ),
        to: result
      )
    }
    return .output(result)
  }

  private mutating func processOpenedRecordStep(
    _ opened: (
      content: OwnedBytes,
      contentType: DTLS13RecordContentType,
      epoch: TLS13HandshakeEpoch,
      recordNumber: DTLS13RecordNumber
    ),
    result: inout DTLSActionBatch,
    implicitlyAcknowledged: inout Bool,
    handshakeRecordNumbersToAcknowledge:
      inout ContiguousArray<DTLS13RecordNumber>
  ) throws(DTLS13ConnectionError) -> TLS13CapabilityRequest? {
    if opened.contentType == .acknowledgment {
      let acknowledgment: DTLS13Acknowledgment
      do {
        acknowledgment = try RFC9147DTLS13AcknowledgmentCodec().parse(
          opened.content.span
        )
      } catch let error {
        throw .acknowledgment(error)
      }
      let acknowledgmentOutput = try receiveAcknowledgment(acknowledgment)
      if acknowledgmentOutput.actions.contains(.handshakeConfirmed) {
        isHandshakeConfirmed = true
      }
      result = try DTLSActionBatchCombiner.appending(
        acknowledgmentOutput,
        to: result
      )
      return nil
    }
    if !core.isEstablished,
      !implicitlyAcknowledged,
      flightController.hasOutstandingFlight
    {
      result = try DTLSActionBatchCombiner.appending(
        mapFlight { try $0.receiveImplicitAcknowledgment() },
        to: result
      )
      implicitlyAcknowledged = true
    }
    if opened.contentType == .applicationData {
      guard core.isEstablished else { throw .invalidState }
      result = try DTLSActionBatchCombiner.appending(
        try DTLS13ApplicationRecordIO.deliver(opened.content),
        to: result
      )
      return nil
    }
    guard opened.contentType == .handshake else {
      throw .malformedDatagram
    }
    if core.isEstablished {
      acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
    }
    return try processHandshakeContentStep(
      opened.content.span,
      at: opened.epoch,
      result: &result
    )
  }

  private mutating func processHandshakeContentStep(
    _ content: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch,
    result: inout DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> TLS13CapabilityRequest? {
    let fragments: ContiguousArray<DTLS13HandshakeFragment>
    do {
      fragments = try RFC9147DTLS13HandshakeFragmentCodec().fragments(
        in: content
      )
      for fragment in fragments {
        try reassembler.receive(fragment, from: content)
      }
    } catch let error {
      throw .fragment(error)
    }
    return try drainHandshakeMessagesStep(at: epoch, result: &result)
  }

  private mutating func drainHandshakeMessagesStep(
    at epoch: TLS13HandshakeEpoch,
    result: inout DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> TLS13CapabilityRequest? {
    while let message = reassembler.takeNextMessage() {
      if core.isEstablished {
        if !message.isEmpty,
          message[0] == TLS13HandshakeCodec.certificateRequestType
        {
          let transition: TLS13HandshakeCoreTransition
          do {
            transition = try core
              .receivePostHandshakeAuthenticationRequestStep(message.span)
          } catch let error {
            throw .handshake(error)
          }
          switch consume transition {
          case .output(let output):
            result = try DTLSActionBatchCombiner.appending(
              try transmit(output),
              to: result
            )
          case .suspended(let request):
            pendingCapabilityEpoch = epoch
            return request
          }
        } else {
          result = try DTLSActionBatchCombiner.appending(
            try receivePostHandshakeMessage(message.span, at: epoch),
            to: result
          )
        }
        continue
      }
      let transition: TLS13HandshakeCoreTransition
      do {
        transition = try core.receiveHandshakeMessageStep(
          message.span,
          at: epoch
        )
      } catch let error {
        throw .handshake(error)
      }
      switch consume transition {
      case .output(let output):
        result = try DTLSActionBatchCombiner.appending(
          try transmit(output),
          to: result
        )
      case .suspended(let request):
        pendingCapabilityEpoch = epoch
        return request
      }
    }
    return nil
  }

  private mutating func processOpenedRecord(
    _ opened: (
      content: OwnedBytes,
      contentType: DTLS13RecordContentType,
      epoch: TLS13HandshakeEpoch,
      recordNumber: DTLS13RecordNumber
    ),
    result: inout DTLSActionBatch,
    implicitlyAcknowledged: inout Bool,
    handshakeRecordNumbersToAcknowledge:
      inout ContiguousArray<DTLS13RecordNumber>
  ) throws(DTLS13ConnectionError) {
    if opened.contentType == .acknowledgment {
      let acknowledgment: DTLS13Acknowledgment
      do {
        acknowledgment = try RFC9147DTLS13AcknowledgmentCodec().parse(
          opened.content.span
        )
      } catch let error {
        throw .acknowledgment(error)
      }
      let acknowledgmentOutput = try receiveAcknowledgment(acknowledgment)
      if acknowledgmentOutput.actions.contains(.handshakeConfirmed) {
        isHandshakeConfirmed = true
      }
      result = try DTLSActionBatchCombiner.appending(
        acknowledgmentOutput,
        to: result
      )
      return
    }
    if !core.isEstablished,
      !implicitlyAcknowledged,
      flightController.hasOutstandingFlight
    {
      result = try DTLSActionBatchCombiner.appending(
        mapFlight { try $0.receiveImplicitAcknowledgment() },
        to: result
      )
      implicitlyAcknowledged = true
    }
    if opened.contentType == .applicationData {
      guard core.isEstablished else { throw .invalidState }
      result = try DTLSActionBatchCombiner.appending(
        try DTLS13ApplicationRecordIO.deliver(opened.content),
        to: result
      )
      return
    }
    guard opened.contentType == .handshake else {
      throw .malformedDatagram
    }
    if core.isEstablished {
      acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
    }
    result = try DTLSActionBatchCombiner.appending(
      try processHandshakeContent(opened.content.span, at: opened.epoch),
      to: result
    )
  }

  public mutating func sendApplicationData(
    _ content: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard core.isEstablished,
      pendingApplicationWrite == nil,
      var protector = applicationWrite.take()
    else {
      throw .invalidState
    }
    do {
      let batch = try DTLS13ApplicationRecordIO.seal(content, using: &protector)
      applicationWrite = consume protector
      return batch
    } catch {
      applicationWrite = consume protector
      throw error
    }
  }

  public mutating func requestKeyUpdate(
    requestPeerUpdate: Bool
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard isHandshakeConfirmed else {
      throw .keyUpdateRequiresHandshakeConfirmation
    }
    return try startKeyUpdate(requestPeerUpdate: requestPeerUpdate)
  }

  public mutating func retransmissionTimerExpired()
    throws(DTLS13ConnectionError) -> DTLSActionBatch {
    try mapFlight { try $0.retransmissionTimerExpired() }
  }

  private mutating func processHandshakeContent(
    _ content: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let fragments: ContiguousArray<DTLS13HandshakeFragment>
    do {
      fragments = try RFC9147DTLS13HandshakeFragmentCodec().fragments(
        in: content
      )
    } catch let error {
      throw .fragment(error)
    }
    var result = try DTLSActionBatchCombiner.empty()
    for fragment in fragments {
      do {
        try reassembler.receive(fragment, from: content)
      } catch let error {
        throw .fragment(error)
      }
      while let message = reassembler.takeNextMessage() {
        if core.isEstablished {
          result = try DTLSActionBatchCombiner.appending(
            try receivePostHandshakeMessage(message.span, at: epoch),
            to: result
          )
          continue
        }
        let coreOutput: TLS13HandshakeCoreOutput
        do {
          coreOutput = try core.receiveHandshakeMessage(
            message.span,
            at: epoch
          )
        } catch let error {
          throw .handshake(error)
        }
        result = try DTLSActionBatchCombiner.appending(
          try transmit(coreOutput),
          to: result
        )
      }
    }
    return result
  }

  private mutating func receivePostHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard epoch == .application, isHandshakeConfirmed else {
      throw .keyUpdateRequiresHandshakeConfirmation
    }
    if !message.isEmpty,
      message[0] == TLS13HandshakeCodec.certificateRequestType
    {
      let transition: TLS13HandshakeCoreTransition
      do {
        transition = try core
          .receivePostHandshakeAuthenticationRequestStep(message)
      } catch let error {
        throw .handshake(error)
      }
      switch consume transition {
      case .output(let output):
        return try transmit(output)
      case .suspended:
        throw .handshake(.capability(.wrongState))
      }
    }
    let requestPeerUpdate: Bool
    do {
      requestPeerUpdate = try TLS13HandshakeCodec.parseKeyUpdate(message)
    } catch let error {
      throw .handshake(.handshake(error))
    }
    try installPeerApplicationTrafficSecret(endpoint: .server)
    guard requestPeerUpdate else {
      return try DTLSActionBatchCombiner.empty()
    }
    if applicationWrite?.epoch == RFC9147DTLS13RecordProtector.maximumSendingEpoch {
      return try DTLSActionBatchCombiner.empty()
    }
    if pendingApplicationWrite != nil || flightController.hasOutstandingFlight {
      shouldRespondToKeyUpdate = true
      return try DTLSActionBatchCombiner.empty()
    }
    return try startKeyUpdate(requestPeerUpdate: false)
  }

  private mutating func startKeyUpdate(
    requestPeerUpdate: Bool
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard core.isEstablished else { throw .invalidState }
    guard pendingApplicationWrite == nil,
      !flightController.hasOutstandingFlight
    else {
      throw .keyUpdateAlreadyPending
    }
    guard var currentWrite = applicationWrite.take() else {
      throw .invalidState
    }
    guard currentWrite.epoch
      < RFC9147DTLS13RecordProtector.maximumSendingEpoch
    else {
      applicationWrite = consume currentWrite
      throw .applicationEpochExhausted
    }
    let message: OwnedBytes
    do {
      message = try TLS13HandshakeCodec.makeKeyUpdate(
        requestUpdate: requestPeerUpdate
      )
    } catch let error {
      applicationWrite = consume currentWrite
      throw .handshake(.handshake(error))
    }
    let nextSecret: TLS13TrafficSecret
    do {
      nextSecret = try core.updateApplicationTrafficSecret(for: .client)
    } catch let error {
      applicationWrite = consume currentWrite
      throw .handshake(error)
    }
    let nextWrite: RFC9147DTLS13RecordProtector
    do {
      nextWrite = try DTLS13ApplicationTrafficKeyUpdater.makeProtector(
        nextSecret,
        epoch: currentWrite.epoch + 1,
        connectionID: peerConnectionID
      )
    } catch let error {
      applicationWrite = consume currentWrite
      throw error
    }
    let flight: DTLS13Flight
    do {
      flight = try DTLS13HandshakeCoreOutputAdapter
        .makeApplicationHandshakeFlight(
          message: message.span,
          maximumDatagramByteCount: maximumDatagramByteCount,
          destinationConnectionIDByteCount: peerConnectionID.count,
          nextMessageSequence: &nextMessageSequence,
          applicationWrite: &currentWrite
        )
    } catch let error {
      applicationWrite = consume currentWrite
      throw error
    }
    applicationWrite = consume currentWrite
    pendingApplicationWrite = consume nextWrite
    return try mapFlight { try $0.startFlight(flight) }
  }

  private mutating func installPeerApplicationTrafficSecret(
    endpoint: TLSRole
  ) throws(DTLS13ConnectionError) {
    guard let currentRead = applicationRead.take() else {
      throw .invalidState
    }
    guard currentRead.epoch < UInt64.max else {
      applicationRead = consume currentRead
      throw .applicationEpochExhausted
    }
    let secret: TLS13TrafficSecret
    do {
      secret = try core.updateApplicationTrafficSecret(for: endpoint)
    } catch let error {
      applicationRead = consume currentRead
      throw .handshake(error)
    }
    let nextRead: RFC9147DTLS13RecordProtector
    do {
      nextRead = try DTLS13ApplicationTrafficKeyUpdater.makeProtector(
        secret,
        epoch: currentRead.epoch + 1,
        connectionID: localConnectionID
      )
    } catch let error {
      applicationRead = consume currentRead
      throw error
    }
    let retainedEpoch = currentRead.epoch
    acknowledgedHandshakeRecordNumbers = Set(
      acknowledgedHandshakeRecordNumbers.lazy.filter {
        $0.epoch >= retainedEpoch
      }
    )
    previousApplicationRead = consume currentRead
    applicationRead = consume nextRead
  }

  private mutating func receiveAcknowledgment(
    _ acknowledgment: DTLS13Acknowledgment
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let output = try mapFlight {
      try $0.receiveAcknowledgment(acknowledgment)
    }
    guard !flightController.hasOutstandingFlight,
      let pendingWrite = pendingApplicationWrite.take()
    else {
      return output
    }
    applicationWrite = consume pendingWrite
    guard shouldRespondToKeyUpdate else { return output }
    shouldRespondToKeyUpdate = false
    return try DTLSActionBatchCombiner.appending(
      try startKeyUpdate(requestPeerUpdate: false),
      to: output
    )
  }

  private mutating func makeAcknowledgment(
    recordNumbers: consuming ContiguousArray<DTLS13RecordNumber>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard var protector = applicationWrite.take() else {
      throw .invalidState
    }
    do {
      let result = try DTLS13ApplicationRecordIO.makeAcknowledgment(
        recordNumbers: recordNumbers,
        using: &protector
      )
      applicationWrite = consume protector
      return result
    } catch let error {
      applicationWrite = consume protector
      throw error
    }
  }

  private func uniqueSorted(
    _ recordNumbers: consuming ContiguousArray<DTLS13RecordNumber>
  ) -> ContiguousArray<DTLS13RecordNumber> {
    var sorted = recordNumbers
    sorted.sort()
    var unique = ContiguousArray<DTLS13RecordNumber>()
    for recordNumber in sorted where unique.last != recordNumber {
      unique.append(recordNumber)
    }
    return unique
  }

  private mutating func transmit(
    _ coreOutput: consuming TLS13HandshakeCoreOutput
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let adaptation = try DTLS13HandshakeCoreOutputAdapter.adapt(
      coreOutput,
      role: .client,
      maximumDatagramByteCount: maximumDatagramByteCount,
      destinationConnectionID: peerConnectionID,
      sourceConnectionID: localConnectionID,
      nextMessageSequence: &nextMessageSequence,
      nextInitialRecordSequence: &nextInitialRecordSequence,
      handshakeRead: &handshakeRead,
      handshakeWrite: &handshakeWrite,
      applicationRead: &applicationRead,
      applicationWrite: &applicationWrite
    )
    let batch: DTLSActionBatch
    if let flight = adaptation.flight {
      batch = try mapFlight { try $0.startFlight(flight) }
    } else {
      batch = try DTLSActionBatchCombiner.empty()
    }
    return try DTLSActionBatchCombiner.appending(
      adaptation.terminalActions,
      to: batch
    )
  }

  private mutating func openProtectedRecord(
    _ record: Span<UInt8>,
    epochBits: UInt8
  ) throws(DTLS13ConnectionError) -> (
    content: OwnedBytes,
    contentType: DTLS13RecordContentType,
    epoch: TLS13HandshakeEpoch,
    recordNumber: DTLS13RecordNumber
  ) {
    switch epochBits {
    case 2:
      guard var protector = handshakeRead.take() else {
        throw .unexpectedEpoch(epochBits)
      }
      do {
        let opened = try Self.open(record, using: &protector)
        handshakeRead = consume protector
        return (
          opened.content,
          opened.contentType,
          .handshake,
          opened.recordNumber
        )
      } catch let error as DTLS13RecordError {
        handshakeRead = consume protector
        throw .record(error)
      } catch {
        handshakeRead = consume protector
        throw .malformedDatagram
      }
    default:
      if let currentEpoch = applicationRead?.epoch,
        currentEpoch & 0x03 == UInt64(epochBits)
      {
        guard var protector = applicationRead.take() else {
          throw .unexpectedEpoch(epochBits)
        }
        do {
          let opened = try Self.open(record, using: &protector)
          applicationRead = consume protector
          previousApplicationRead = nil
          return (
            opened.content,
            opened.contentType,
            .application,
            opened.recordNumber
          )
        } catch let error as DTLS13RecordError {
          applicationRead = consume protector
          throw .record(error)
        } catch {
          applicationRead = consume protector
          throw .malformedDatagram
        }
      }
      guard let previousEpoch = previousApplicationRead?.epoch,
        previousEpoch & 0x03 == UInt64(epochBits),
        var protector = previousApplicationRead.take()
      else {
        throw .unexpectedEpoch(epochBits)
      }
      do {
        let opened = try Self.open(record, using: &protector)
        previousApplicationRead = consume protector
        return (
          opened.content,
          opened.contentType,
          .application,
          opened.recordNumber
        )
      } catch let error as DTLS13RecordError {
        previousApplicationRead = consume protector
        throw .record(error)
      } catch {
        previousApplicationRead = consume protector
        throw .malformedDatagram
      }
    }
  }

  private static func open(
    _ record: Span<UInt8>,
    using protector: inout RFC9147DTLS13RecordProtector
  ) throws(DTLS13RecordError) -> (
    content: OwnedBytes,
    contentType: DTLS13RecordContentType,
    recordNumber: DTLS13RecordNumber
  ) {
    var output = ContiguousArray<UInt8>(repeating: 0, count: record.count)
    let contentType = try output.withUnsafeMutableBufferPointer {
      buffer throws(DTLS13RecordError) in
      var destination = MutableSpan(
        _unsafeStart: buffer.baseAddress!,
        count: buffer.count
      )
      return try protector.open(record: record, into: &destination)
    }
    output.removeLast(output.count - protector.lastOpenedByteCount)
    guard let recordNumber = protector.lastOpenedRecordNumber else {
      throw .malformedRecord
    }
    return (OwnedBytes(consuming: output), contentType, recordNumber)
  }

  private mutating func mapFlight(
    _ body: (inout RFC9147DTLS13FlightController) throws -> DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    do {
      return try body(&flightController)
    } catch let error as DTLS13FlightError {
      throw .flight(error)
    } catch {
      throw .invalidState
    }
  }
}
