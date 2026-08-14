import SSLCore
import SSLCrypto

/// Deterministic DTLS 1.3 server composed from the shared TLS semantic core.
public struct DTLS13ServerHandshake: DTLS13ServerHandshaking, ~Copyable, Sendable {
  private var core: TLS13ServerHandshakeCore
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
  private var pendingHandshakeRecordNumbers:
    ContiguousArray<DTLS13RecordNumber>
  private var shouldRespondToKeyUpdate: Bool
  private var pendingCapabilityDatagram: OwnedBytes?
  private var pendingCapabilityEpoch: TLS13HandshakeEpoch?
  private var pendingCapabilityPeer: DTLS13PeerContext?
  private let cookieProtector: any DTLS13CookieProtecting
  private var activePeerIdentity: OwnedBytes?
  private var pendingInitialClientHelloHash: OwnedBytes?
  private var pendingRetryCipherSuite: TLSCipherSuite?
  private let localConnectionID: OwnedBytes
  private let peerConnectionID: OwnedBytes
  private let maximumDatagramByteCount: Int
  private var nextMessageSequence: UInt32
  private var nextInitialRecordSequence: UInt64

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
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
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
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
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
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
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    ephemeralKey: consuming X25519PrivateKey,
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
    let core: TLS13ServerHandshakeCore
    do {
      core = try TLS13ServerHandshakeCore(
        random: random,
        ephemeralKey: ephemeralKey,
        externalServerCredential: externalServerCredential,
        verificationInstant: verificationInstant,
        applicationProtocolSelector: applicationProtocolSelector,
        clientAuthentication: clientAuthentication,
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13P256ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
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
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  public static func make(
    random: Span<UInt8>,
    keyExchange: consuming TLS13X25519MLKEM768ServerKeyExchange,
    keyExchangeEntropy: consuming any EntropySource = SystemEntropySource(),
    externalServerCredential: TLS13ExternalServerCredential,
    verificationInstant: VerificationInstant,
    cookieProtector: any DTLS13CookieProtecting,
    applicationProtocolSelector:
      (any TLS13ApplicationProtocolSelecting)? = nil,
    clientAuthentication: TLS13ClientAuthenticationConfiguration? = nil,
    srtpConfiguration: DTLSSRTPServerConfiguration? = nil,
    localConnectionID: Span<UInt8>? = nil,
    peerConnectionID: Span<UInt8>? = nil,
    maximumDatagramByteCount: Int = 1_200
  ) throws(DTLS13ConnectionError) -> Self {
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
        handshakeEncoding: .dtls13
      )
    } catch let error {
      throw .handshake(error)
    }
    return try make(
      core: core,
      cookieProtector: cookieProtector,
      srtpConfiguration: srtpConfiguration,
      localConnectionID: localConnectionID,
      peerConnectionID: peerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount
    )
  }

  private static func make(
    core: consuming TLS13ServerHandshakeCore,
    cookieProtector: any DTLS13CookieProtecting,
    srtpConfiguration: DTLSSRTPServerConfiguration?,
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
      pendingHandshakeRecordNumbers: [],
      shouldRespondToKeyUpdate: false,
      pendingCapabilityDatagram: nil,
      pendingCapabilityEpoch: nil,
      pendingCapabilityPeer: nil,
      cookieProtector: cookieProtector,
      activePeerIdentity: nil,
      pendingInitialClientHelloHash: nil,
      pendingRetryCipherSuite: nil,
      localConnectionID: ownedLocalConnectionID,
      peerConnectionID: ownedPeerConnectionID,
      maximumDatagramByteCount: maximumDatagramByteCount,
      nextMessageSequence: 0,
      nextInitialRecordSequence: 0
    )
  }

  private init(
    core: consuming TLS13ServerHandshakeCore,
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
    pendingHandshakeRecordNumbers:
      consuming ContiguousArray<DTLS13RecordNumber>,
    shouldRespondToKeyUpdate: Bool,
    pendingCapabilityDatagram: consuming OwnedBytes?,
    pendingCapabilityEpoch: TLS13HandshakeEpoch?,
    pendingCapabilityPeer: consuming DTLS13PeerContext?,
    cookieProtector: any DTLS13CookieProtecting,
    activePeerIdentity: consuming OwnedBytes?,
    pendingInitialClientHelloHash: consuming OwnedBytes?,
    pendingRetryCipherSuite: TLSCipherSuite?,
    localConnectionID: consuming OwnedBytes,
    peerConnectionID: consuming OwnedBytes,
    maximumDatagramByteCount: Int,
    nextMessageSequence: UInt32,
    nextInitialRecordSequence: UInt64
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
    self.pendingHandshakeRecordNumbers = pendingHandshakeRecordNumbers
    self.shouldRespondToKeyUpdate = shouldRespondToKeyUpdate
    self.pendingCapabilityDatagram = pendingCapabilityDatagram
    self.pendingCapabilityEpoch = pendingCapabilityEpoch
    self.pendingCapabilityPeer = pendingCapabilityPeer
    self.cookieProtector = cookieProtector
    self.activePeerIdentity = activePeerIdentity
    self.pendingInitialClientHelloHash = pendingInitialClientHelloHash
    self.pendingRetryCipherSuite = pendingRetryCipherSuite
    self.localConnectionID = localConnectionID
    self.peerConnectionID = peerConnectionID
    self.maximumDatagramByteCount = maximumDatagramByteCount
    self.nextMessageSequence = nextMessageSequence
    self.nextInitialRecordSequence = nextInitialRecordSequence
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

  public var authenticatedClientIdentity: TLS13ValidatedClientCertificate? {
    core.authenticatedClientIdentity
  }

  public mutating func receiveDatagram(
    _ datagram: Span<UInt8>,
    from peer: DTLS13PeerContext
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    if let activePeerIdentity,
      !ConstantTime.equal(activePeerIdentity.span, peer.identity.span)
    {
      throw .cookie(.authenticationFailed)
    }
    let records: ContiguousArray<DTLS13DatagramRecord>
    do {
      records = try RFC9147DTLS13DatagramRecordFramer(
        expectedConnectionIDByteCount: localConnectionID.count
      ).records(in: datagram)
    } catch let error {
      throw .record(error)
    }
    var result = try DTLSActionBatchCombiner.empty()
    var finalFlightRecordNumbers = ContiguousArray<DTLS13RecordNumber>()
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
        let content = recordBytes.extracting(
          parsed.fragment.offset..<parsed.fragment.endOffset
        )
        if !implicitlyAcknowledged, flightController.hasOutstandingFlight {
          result = try DTLSActionBatchCombiner.appending(
            mapFlight { try $0.receiveImplicitAcknowledgment() },
            to: result
          )
          implicitlyAcknowledged = true
        }
        result = try DTLSActionBatchCombiner.appending(
          try processHandshakeContent(content, at: .initial, from: peer),
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
            from: peer,
            result: &result,
            implicitlyAcknowledged: &implicitlyAcknowledged,
            handshakeRecordNumbersToAcknowledge: &finalFlightRecordNumbers
          )
        } catch let error {
          if case .record(.replayed(let recordNumber)) = error {
            if acknowledgedHandshakeRecordNumbers.contains(recordNumber) {
              finalFlightRecordNumbers.append(recordNumber)
            }
            continue
          }
          throw error
        }
      }
    }
    if core.isEstablished, !finalFlightRecordNumbers.isEmpty {
      finalFlightRecordNumbers.sort()
      var unique = ContiguousArray<DTLS13RecordNumber>()
      for recordNumber in finalFlightRecordNumbers
      where unique.last != recordNumber {
        unique.append(recordNumber)
      }
      result = try DTLSActionBatchCombiner.appending(
        try makeAcknowledgment(recordNumbers: unique),
        to: result
      )
    }
    return result
  }

  public mutating func receiveDatagramStep(
    _ datagram: Span<UInt8>,
    from peer: DTLS13PeerContext
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    guard pendingCapabilityDatagram == nil,
      pendingCapabilityEpoch == nil,
      pendingCapabilityPeer == nil
    else {
      throw .invalidState
    }
    return try receiveDatagramStepInternal(datagram, from: peer)
  }

  public mutating func resume(
    _ response: TLS13CapabilityResponse
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    guard let epoch = pendingCapabilityEpoch,
      let peer = pendingCapabilityPeer
    else {
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
      from: peer,
      result: &result
    ) {
      return .suspended(request, result)
    }
    if core.isEstablished, !pendingHandshakeRecordNumbers.isEmpty {
      let recordNumbers = uniqueSorted(pendingHandshakeRecordNumbers)
      for recordNumber in recordNumbers {
        acknowledgedHandshakeRecordNumbers.insert(recordNumber)
      }
      pendingHandshakeRecordNumbers.removeAll(keepingCapacity: true)
      result = try DTLSActionBatchCombiner.appending(
        try makeAcknowledgment(recordNumbers: recordNumbers),
        to: result
      )
    }
    pendingCapabilityPeer = nil
    guard let remainder = pendingCapabilityDatagram.take() else {
      return .output(result)
    }
    let remainderTransition = try receiveDatagramStepInternal(
      remainder.span,
      from: peer
    )
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
    _ datagram: Span<UInt8>,
    from peer: DTLS13PeerContext
  ) throws(DTLS13ConnectionError) -> DTLS13HandshakeTransition {
    if let activePeerIdentity,
      !ConstantTime.equal(activePeerIdentity.span, peer.identity.span)
    {
      throw .cookie(.authenticationFailed)
    }
    let records: ContiguousArray<DTLS13DatagramRecord>
    do {
      records = try RFC9147DTLS13DatagramRecordFramer(
        expectedConnectionIDByteCount: localConnectionID.count
      ).records(in: datagram)
    } catch let error {
      throw .record(error)
    }
    var result = try DTLSActionBatchCombiner.empty()
    var finalFlightRecordNumbers = ContiguousArray<DTLS13RecordNumber>()
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
          from: peer,
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
            from: peer,
            result: &result,
            implicitlyAcknowledged: &implicitlyAcknowledged,
            handshakeRecordNumbersToAcknowledge: &finalFlightRecordNumbers
          )
        } catch let error {
          if case .record(.replayed(let recordNumber)) = error {
            if acknowledgedHandshakeRecordNumbers.contains(recordNumber) {
              finalFlightRecordNumbers.append(recordNumber)
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
        pendingCapabilityPeer = peer
        if core.isEstablished, !finalFlightRecordNumbers.isEmpty {
          let recordNumbers = uniqueSorted(finalFlightRecordNumbers)
          result = try DTLSActionBatchCombiner.appending(
            try makeAcknowledgment(recordNumbers: recordNumbers),
            to: result
          )
        }
        return .suspended(request, result)
      }
    }
    if core.isEstablished, !finalFlightRecordNumbers.isEmpty {
      result = try DTLSActionBatchCombiner.appending(
        try makeAcknowledgment(
          recordNumbers: uniqueSorted(finalFlightRecordNumbers)
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
    from peer: DTLS13PeerContext,
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
      result = try DTLSActionBatchCombiner.appending(
        try receiveAcknowledgment(acknowledgment),
        to: result
      )
      return nil
    }
    if !core.isEstablished,
      !implicitlyAcknowledged,
      flightController.hasOutstandingFlight
    {
      result = try DTLSActionBatchCombiner.appending(
        try mapFlight { try $0.receiveImplicitAcknowledgment() },
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
    let wasEstablished = core.isEstablished
    let request = try processHandshakeContentStep(
      opened.content.span,
      at: opened.epoch,
      from: peer,
      result: &result
    )
    if core.isEstablished {
      if wasEstablished {
        handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
        acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      } else {
        for recordNumber in pendingHandshakeRecordNumbers {
          handshakeRecordNumbersToAcknowledge.append(recordNumber)
          acknowledgedHandshakeRecordNumbers.insert(recordNumber)
        }
        pendingHandshakeRecordNumbers.removeAll(keepingCapacity: true)
        handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
        acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      }
    } else {
      pendingHandshakeRecordNumbers.append(opened.recordNumber)
    }
    return request
  }

  private mutating func processHandshakeContentStep(
    _ content: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch,
    from peer: DTLS13PeerContext,
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
    return try drainHandshakeMessagesStep(
      at: epoch,
      from: peer,
      result: &result
    )
  }

  private mutating func drainHandshakeMessagesStep(
    at epoch: TLS13HandshakeEpoch,
    from peer: DTLS13PeerContext,
    result: inout DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> TLS13CapabilityRequest? {
    while let message = reassembler.takeNextMessage() {
      if core.isEstablished {
        if !message.isEmpty,
          message[0] != TLS13HandshakeCodec.keyUpdateType
        {
          let transition: TLS13HandshakeCoreTransition
          do {
            transition = try core.receiveHandshakeMessageStep(
              message.span,
              at: .application
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
            pendingCapabilityPeer = peer
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
      let transition = try receiveHandshakeMessageStep(
        message.span,
        at: epoch,
        from: peer
      )
      switch consume transition {
      case .output(let output):
        result = try DTLSActionBatchCombiner.appending(
          try transmit(output),
          to: result
        )
      case .suspended(let request):
        pendingCapabilityEpoch = epoch
        pendingCapabilityPeer = peer
        return request
      }
    }
    return nil
  }

  private mutating func receiveHandshakeMessageStep(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch,
    from peer: DTLS13PeerContext
  ) throws(DTLS13ConnectionError) -> TLS13HandshakeCoreTransition {
    guard epoch == .initial || !core.isAwaitingInitialClientHello else {
      throw .invalidState
    }
    if core.isAwaitingInitialClientHello {
      let output = try receiveHandshakeMessage(
        message,
        at: epoch,
        from: peer
      )
      return .output(output)
    }
    if core.isAwaitingSecondClientHello {
      let parsed: TLS13ClientHello
      do {
        parsed = try TLS13HandshakeCodec.parseClientHello(
          message,
          encoding: .dtls13
        )
      } catch let error {
        throw .handshake(.handshake(error))
      }
      guard let cookie = parsed.cookie,
        let expectedHash = pendingInitialClientHelloHash,
        let expectedCipherSuite = pendingRetryCipherSuite
      else {
        throw .handshake(.malformedInput)
      }
      let validation: DTLS13CookieValidation
      do {
        validation = try cookieProtector.validateCookie(
          cookie.span,
          peerIdentity: peer.identity.span,
          at: peer.receivedAt
        )
      } catch let error {
        throw .cookie(error)
      }
      guard ConstantTime.equal(
        validation.clientHelloHash.span,
        expectedHash.span
      ), validation.cipherSuite == expectedCipherSuite else {
        throw .cookie(.authenticationFailed)
      }
      pendingInitialClientHelloHash = nil
      pendingRetryCipherSuite = nil
    }
    do {
      return try core.receiveHandshakeMessageStep(message, at: epoch)
    } catch let error {
      throw .handshake(error)
    }
  }

  private mutating func processOpenedRecord(
    _ opened: (
      content: OwnedBytes,
      contentType: DTLS13RecordContentType,
      epoch: TLS13HandshakeEpoch,
      recordNumber: DTLS13RecordNumber
    ),
    from peer: DTLS13PeerContext,
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
      result = try DTLSActionBatchCombiner.appending(
        try receiveAcknowledgment(acknowledgment),
        to: result
      )
      return
    }
    if !core.isEstablished,
      !implicitlyAcknowledged,
      flightController.hasOutstandingFlight
    {
      result = try DTLSActionBatchCombiner.appending(
        try mapFlight { try $0.receiveImplicitAcknowledgment() },
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
    let wasEstablished = core.isEstablished
    result = try DTLSActionBatchCombiner.appending(
      try processHandshakeContent(
        opened.content.span,
        at: opened.epoch,
        from: peer
      ),
      to: result
    )
    if core.isEstablished {
      if wasEstablished {
        handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
        acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      } else {
        for recordNumber in pendingHandshakeRecordNumbers {
          handshakeRecordNumbersToAcknowledge.append(recordNumber)
          acknowledgedHandshakeRecordNumbers.insert(recordNumber)
        }
        pendingHandshakeRecordNumbers.removeAll(keepingCapacity: true)
        handshakeRecordNumbersToAcknowledge.append(opened.recordNumber)
        acknowledgedHandshakeRecordNumbers.insert(opened.recordNumber)
      }
    } else {
      pendingHandshakeRecordNumbers.append(opened.recordNumber)
    }
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
    try startKeyUpdate(requestPeerUpdate: requestPeerUpdate)
  }

  public mutating func requestPostHandshakeClientAuthentication(
    requestContext: Span<UInt8>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard core.isEstablished,
      pendingApplicationWrite == nil,
      !flightController.hasOutstandingFlight
    else {
      throw .invalidState
    }
    let output: TLS13HandshakeCoreOutput
    do {
      output = try core.requestPostHandshakeClientAuthentication(
        requestContext: requestContext
      )
    } catch let error {
      throw .handshake(error)
    }
    return try transmit(output)
  }

  public mutating func retransmissionTimerExpired()
    throws(DTLS13ConnectionError) -> DTLSActionBatch {
    try mapFlight { try $0.retransmissionTimerExpired() }
  }

  private mutating func processHandshakeContent(
    _ content: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch,
    from peer: DTLS13PeerContext
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
        let coreOutput = try receiveHandshakeMessage(
          message.span,
          at: epoch,
          from: peer
        )
        result = try DTLSActionBatchCombiner.appending(
          try transmit(coreOutput),
          to: result
        )
      }
    }
    return result
  }

  private mutating func receiveHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch,
    from peer: DTLS13PeerContext
  ) throws(DTLS13ConnectionError) -> TLS13HandshakeCoreOutput {
    guard epoch == .initial || !core.isAwaitingInitialClientHello else {
      throw .invalidState
    }
    if core.isAwaitingInitialClientHello {
      let selectedCipherSuite: TLSCipherSuite
      do {
        selectedCipherSuite = try core.prepareHelloRetryRequest(for: message)
      } catch let error {
        throw .handshake(error)
      }
      let clientHelloHash = try hashClientHello(
        message,
        cipherSuite: selectedCipherSuite
      )
      let cookie: OwnedBytes
      do {
        cookie = try cookieProtector.issueCookie(
          clientHelloHash: clientHelloHash.span,
          cipherSuite: selectedCipherSuite,
          peerIdentity: peer.identity.span,
          at: peer.receivedAt
        )
      } catch let error {
        throw .cookie(error)
      }
      pendingInitialClientHelloHash = clientHelloHash
      pendingRetryCipherSuite = selectedCipherSuite
      activePeerIdentity = OwnedBytes(copying: peer.identity.span)
      do {
        return try core.completeHelloRetryRequest(cookie: cookie.span)
      } catch let error {
        throw .handshake(error)
      }
    }
    if core.isAwaitingSecondClientHello {
      let parsed: TLS13ClientHello
      do {
        parsed = try TLS13HandshakeCodec.parseClientHello(
          message,
          encoding: .dtls13
        )
      } catch let error {
        throw .handshake(.handshake(error))
      }
      guard let cookie = parsed.cookie,
        let expectedHash = pendingInitialClientHelloHash,
        let expectedCipherSuite = pendingRetryCipherSuite
      else {
        throw .handshake(.malformedInput)
      }
      let validation: DTLS13CookieValidation
      do {
        validation = try cookieProtector.validateCookie(
          cookie.span,
          peerIdentity: peer.identity.span,
          at: peer.receivedAt
        )
      } catch let error {
        throw .cookie(error)
      }
      guard ConstantTime.equal(
        validation.clientHelloHash.span,
        expectedHash.span
      ), validation.cipherSuite == expectedCipherSuite else {
        throw .cookie(.authenticationFailed)
      }
      pendingInitialClientHelloHash = nil
      pendingRetryCipherSuite = nil
    }
    do {
      return try core.receiveHandshakeMessage(message, at: epoch)
    } catch let error {
      throw .handshake(error)
    }
  }

  private func hashClientHello(
    _ message: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(DTLS13ConnectionError) -> OwnedBytes {
    do {
      var transcript = try TLS13Transcript()
      try transcript.append(message)
      return try transcript.digest(for: cipherSuite)
    } catch let error {
      throw .handshake(.handshake(error))
    }
  }

  private mutating func receivePostHandshakeMessage(
    _ message: Span<UInt8>,
    at epoch: TLS13HandshakeEpoch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    guard epoch == .application else { throw .invalidState }
    if !message.isEmpty, message[0] != TLS13HandshakeCodec.keyUpdateType {
      let output: TLS13HandshakeCoreOutput
      do {
        output = try core.receiveHandshakeMessage(message, at: .application)
      } catch let error {
        throw .handshake(error)
      }
      return try transmit(output)
    }
    let requestPeerUpdate: Bool
    do {
      requestPeerUpdate = try TLS13HandshakeCodec.parseKeyUpdate(message)
    } catch let error {
      throw .handshake(.handshake(error))
    }
    try installPeerApplicationTrafficSecret(endpoint: .client)
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
      nextSecret = try core.updateApplicationTrafficSecret(for: .server)
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

  private mutating func transmit(
    _ coreOutput: consuming TLS13HandshakeCoreOutput
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    let adaptation = try DTLS13HandshakeCoreOutputAdapter.adapt(
      coreOutput,
      role: .server,
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
      } catch let error {
        handshakeRead = consume protector
        throw .record(error)
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
        } catch let error {
          applicationRead = consume protector
          throw .record(error)
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
      } catch let error {
        previousApplicationRead = consume protector
        throw .record(error)
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
import TLSTypes
