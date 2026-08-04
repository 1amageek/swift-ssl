import SSLCore
import SSLCrypto

enum DTLS13HandshakeCoreOutputAdapter {
  static func adapt(
    _ coreOutput: consuming TLS13HandshakeCoreOutput,
    role: TLSRole,
    maximumDatagramByteCount: Int,
    destinationConnectionID: borrowing OwnedBytes,
    sourceConnectionID: borrowing OwnedBytes,
    nextMessageSequence: inout UInt32,
    nextInitialRecordSequence: inout UInt64,
    handshakeRead: inout RFC9147DTLS13RecordProtector?,
    handshakeWrite: inout RFC9147DTLS13RecordProtector?,
    applicationRead: inout RFC9147DTLS13RecordProtector?,
    applicationWrite: inout RFC9147DTLS13RecordProtector?
  ) throws(DTLS13ConnectionError) -> DTLS13CoreAdaptation {
    var coreOutput = consume coreOutput
    var flightBytes = ContiguousArray<UInt8>()
    var datagrams = ContiguousArray<DTLS13FlightDatagram>()
    var terminalActions = ContiguousArray<DTLSAction>()
    var isFinalFlight = false
    do {
      while let effect = try coreOutput.nextEffect() {
        switch consume effect {
        case .action(let action):
          switch action {
          case .emitHandshakeBytes(let epoch, let range):
            let emitted = try coreOutput.bytes.span(in: range)
            let messageRanges = try TLS13HandshakeWire.handshakeMessageRanges(emitted)
            for messageRange in messageRanges {
              guard nextMessageSequence <= UInt16.max else {
                throw DTLS13HandshakeFragmentError.messageSequenceExhausted
              }
              let message = emitted.extracting(
                messageRange.offset..<messageRange.endOffset
              )
              try appendMessage(
                message,
                messageSequence: UInt16(nextMessageSequence),
                epoch: epoch,
                maximumDatagramByteCount: maximumDatagramByteCount,
                destinationConnectionIDByteCount: destinationConnectionID.count,
                flightBytes: &flightBytes,
                datagrams: &datagrams,
                nextInitialRecordSequence: &nextInitialRecordSequence,
                handshakeWrite: &handshakeWrite,
                applicationWrite: &applicationWrite
              )
              nextMessageSequence += 1
            }
          case .installEarlyTrafficSecret, .installTrafficSecrets,
               .earlyDataAccepted, .earlyDataRejected:
            throw DTLS13ConnectionError.invalidState
          case .handshakeComplete:
            terminalActions.append(.handshakeComplete)
            isFinalFlight = !datagrams.isEmpty
          case .handshakeConfirmed:
            terminalActions.append(.handshakeConfirmed)
          }
        case .trafficSecrets(let epoch, let secrets):
          try install(
            secrets,
            epoch: epoch,
            role: role,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            handshakeRead: &handshakeRead,
            handshakeWrite: &handshakeWrite,
            applicationRead: &applicationRead,
            applicationWrite: &applicationWrite
          )
        case .earlyTrafficSecret:
          throw DTLS13ConnectionError.invalidState
        }
      }
    } catch let error as DTLS13ConnectionError {
      throw error
    } catch let error as TLS13HandshakeCoreOutputError {
      switch error {
      case .byteRange(let byteError): throw .output(byteError)
      case .duplicateTrafficSecrets, .missingTrafficSecrets,
           .unreferencedTrafficSecrets, .duplicateEarlyTrafficSecret,
           .missingEarlyTrafficSecret, .unreferencedEarlyTrafficSecret:
        throw .invalidState
      }
    } catch let error as TLS13HandshakeEngineError {
      throw .handshake(error)
    } catch let error as DTLS13HandshakeFragmentError {
      throw .fragment(error)
    } catch let error as DTLS13RecordError {
      throw .record(error)
    } catch let error as DTLS13FlightError {
      throw .flight(error)
    } catch let error as ByteError {
      throw .output(error)
    } catch {
      throw .invalidState
    }

    let flight: DTLS13Flight?
    if datagrams.isEmpty {
      flight = nil
    } else {
      do {
        flight = try DTLS13Flight(
          bytes: OwnedBytes(consuming: flightBytes),
          datagrams: datagrams,
          isFinalFlight: isFinalFlight
        )
      } catch let error {
        throw .flight(error)
      }
    }
    return DTLS13CoreAdaptation(
      flight: flight,
      terminalActions: terminalActions
    )
  }

  static func makeApplicationHandshakeFlight(
    message: Span<UInt8>,
    maximumDatagramByteCount: Int,
    destinationConnectionIDByteCount: Int,
    nextMessageSequence: inout UInt32,
    applicationWrite: inout RFC9147DTLS13RecordProtector
  ) throws(DTLS13ConnectionError) -> DTLS13Flight {
    guard nextMessageSequence <= UInt16.max else {
      throw .fragment(.messageSequenceExhausted)
    }
    guard message.count >= 4 else { throw .malformedDatagram }
    var flightBytes = ContiguousArray<UInt8>()
    var datagrams = ContiguousArray<DTLS13FlightDatagram>()
    do {
      let maximumFragmentBodyByteCount = maximumDatagramByteCount
        - 1 - destinationConnectionIDByteCount - 2 - 2
        - RFC9147DTLS13HandshakeFragmentCodec.headerByteCount
        - 1 - TLS13RecordProtector.tagByteCount
      guard maximumFragmentBodyByteCount > 0 else {
        throw DTLS13ConnectionError.invalidConfiguration
      }
      let codec = try RFC9147DTLS13HandshakeFragmentCodec(
        maximumMessageByteCount:
          TLS13HandshakeMessageFramer.protocolMaximumMessageByteCount
      )
      let messageBodyByteCount = message.count - 4
      var fragmentOffset = 0
      repeat {
        let fragmentByteCount = Swift.min(
          maximumFragmentBodyByteCount,
          messageBodyByteCount - fragmentOffset
        )
        var fragment = ContiguousArray<UInt8>()
        try codec.appendFragment(
          tlsHandshakeMessage: message,
          messageSequence: UInt16(nextMessageSequence),
          fragmentOffset: fragmentOffset,
          fragmentByteCount: fragmentByteCount,
          to: &fragment
        )
        let datagramStart = flightBytes.count
        let recordNumber = try appendProtectedRecord(
          content: fragment.span,
          contentType: .handshake,
          protector: &applicationWrite,
          to: &flightBytes
        )
        datagrams.append(
          try DTLS13FlightDatagram(
            bytes: ByteRange(
              offset: datagramStart,
              count: flightBytes.count - datagramStart
            ),
            recordNumbers: [recordNumber]
          )
        )
        fragmentOffset += fragmentByteCount
      } while fragmentOffset < messageBodyByteCount
      nextMessageSequence += 1
      return try DTLS13Flight(
        bytes: OwnedBytes(consuming: flightBytes),
        datagrams: datagrams,
        isFinalFlight: false
      )
    } catch let error as DTLS13ConnectionError {
      throw error
    } catch let error as DTLS13HandshakeFragmentError {
      throw .fragment(error)
    } catch let error as DTLS13RecordError {
      throw .record(error)
    } catch let error as DTLS13FlightError {
      throw .flight(error)
    } catch let error as ByteError {
      throw .output(error)
    } catch {
      throw .invalidState
    }
  }

  private static func appendMessage(
    _ message: Span<UInt8>,
    messageSequence: UInt16,
    epoch: TLS13HandshakeEpoch,
    maximumDatagramByteCount: Int,
    destinationConnectionIDByteCount: Int,
    flightBytes: inout ContiguousArray<UInt8>,
    datagrams: inout ContiguousArray<DTLS13FlightDatagram>,
    nextInitialRecordSequence: inout UInt64,
    handshakeWrite: inout RFC9147DTLS13RecordProtector?,
    applicationWrite: inout RFC9147DTLS13RecordProtector?
  ) throws {
    let fragmentCodec = try RFC9147DTLS13HandshakeFragmentCodec(
      maximumMessageByteCount: TLS13HandshakeMessageFramer.protocolMaximumMessageByteCount
    )
    let messageBodyByteCount = message.count - 4
    let maximumFragmentBodyByteCount: Int
    switch epoch {
    case .initial:
      maximumFragmentBodyByteCount = maximumDatagramByteCount
        - RFC9147DTLS13PlaintextRecordCodec.headerByteCount
        - RFC9147DTLS13HandshakeFragmentCodec.headerByteCount
    case .earlyData:
      throw DTLS13ConnectionError.invalidState
    case .handshake:
      maximumFragmentBodyByteCount = maximumDatagramByteCount
        - 1 - destinationConnectionIDByteCount - 2 - 2
        - RFC9147DTLS13HandshakeFragmentCodec.headerByteCount
        - 1 - TLS13RecordProtector.tagByteCount
    case .application:
      maximumFragmentBodyByteCount = maximumDatagramByteCount
        - 1 - destinationConnectionIDByteCount - 2 - 2
        - RFC9147DTLS13HandshakeFragmentCodec.headerByteCount
        - 1 - TLS13RecordProtector.tagByteCount
    }
    guard maximumFragmentBodyByteCount > 0 else {
      throw DTLS13ConnectionError.invalidConfiguration
    }

    var fragmentOffset = 0
    repeat {
      let fragmentByteCount = Swift.min(
        maximumFragmentBodyByteCount,
        messageBodyByteCount - fragmentOffset
      )
      var fragment = ContiguousArray<UInt8>()
      try fragmentCodec.appendFragment(
        tlsHandshakeMessage: message,
        messageSequence: messageSequence,
        fragmentOffset: fragmentOffset,
        fragmentByteCount: fragmentByteCount,
        to: &fragment
      )
      let datagramStart = flightBytes.count
      let recordNumber: DTLS13RecordNumber
      switch epoch {
      case .initial:
        let plaintextCodec = RFC9147DTLS13PlaintextRecordCodec()
        try plaintextCodec.appendRecord(
          contentType: .handshake,
          sequenceNumber: nextInitialRecordSequence,
          fragment: fragment.span,
          to: &flightBytes
        )
        recordNumber = try DTLS13RecordNumber(
          epoch: 0,
          sequenceNumber: nextInitialRecordSequence
        )
        nextInitialRecordSequence += 1
      case .earlyData:
        throw DTLS13ConnectionError.invalidState
      case .handshake:
        guard var protector = handshakeWrite.take() else {
          throw DTLS13ConnectionError.invalidState
        }
        do {
          recordNumber = try appendProtectedRecord(
            content: fragment.span,
            contentType: .handshake,
            protector: &protector,
            to: &flightBytes
          )
          handshakeWrite = consume protector
        } catch {
          handshakeWrite = consume protector
          throw error
        }
      case .application:
        guard var protector = applicationWrite.take() else {
          throw DTLS13ConnectionError.invalidState
        }
        do {
          recordNumber = try appendProtectedRecord(
            content: fragment.span,
            contentType: .handshake,
            protector: &protector,
            to: &flightBytes
          )
          applicationWrite = consume protector
        } catch {
          applicationWrite = consume protector
          throw error
        }
      }
      let datagramRange = try ByteRange(
        offset: datagramStart,
        count: flightBytes.count - datagramStart
      )
      datagrams.append(
        try DTLS13FlightDatagram(
          bytes: datagramRange,
          recordNumbers: [recordNumber]
        )
      )
      fragmentOffset += fragmentByteCount
    } while fragmentOffset < messageBodyByteCount
  }

  private static func appendProtectedRecord(
    content: Span<UInt8>,
    contentType: DTLS13RecordContentType,
    protector: inout RFC9147DTLS13RecordProtector,
    to output: inout ContiguousArray<UInt8>
  ) throws(DTLS13RecordError) -> DTLS13RecordNumber {
    let recordByteCount = try protector.sealedRecordByteCount(
      contentByteCount: content.count
    )
    let start = output.count
    output.append(contentsOf: repeatElement(0, count: recordByteCount))
    do {
      return try output.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!.advanced(by: start),
          count: recordByteCount
        )
        return try protector.seal(
          content: content,
          contentType: contentType,
          into: &destination
        )
      }
    } catch let error as DTLS13RecordError {
      output.removeLast(recordByteCount)
      throw error
    } catch {
      output.removeLast(recordByteCount)
      throw .malformedRecord
    }
  }

  private static func install(
    _ pair: consuming TLS13TrafficSecretPair,
    epoch: TLS13HandshakeEpoch,
    role: TLSRole,
    destinationConnectionID: borrowing OwnedBytes,
    sourceConnectionID: borrowing OwnedBytes,
    handshakeRead: inout RFC9147DTLS13RecordProtector?,
    handshakeWrite: inout RFC9147DTLS13RecordProtector?,
    applicationRead: inout RFC9147DTLS13RecordProtector?,
    applicationWrite: inout RFC9147DTLS13RecordProtector?
  ) throws(DTLS13ConnectionError) {
    let pair = consume pair
    let numericEpoch: UInt64
    switch epoch {
    case .initial, .earlyData: throw .invalidState
    case .handshake: numericEpoch = 2
    case .application: numericEpoch = 3
    }
    var readProtector: RFC9147DTLS13RecordProtector?
    var writeProtector: RFC9147DTLS13RecordProtector?
    do {
      switch role {
      case .client:
        readProtector = try pair.withServerSecret {
          secret throws(DTLS13RecordError) in
          try RFC9147DTLS13RecordProtector(
            cipherSuite: pair.cipherSuite,
            trafficSecret: secret,
            epoch: numericEpoch,
            connectionID: sourceConnectionID.isEmpty ? nil : sourceConnectionID.span
          )
        }
        writeProtector = try pair.withClientSecret {
          secret throws(DTLS13RecordError) in
          try RFC9147DTLS13RecordProtector(
            cipherSuite: pair.cipherSuite,
            trafficSecret: secret,
            epoch: numericEpoch,
            connectionID: destinationConnectionID.isEmpty ? nil : destinationConnectionID.span
          )
        }
      case .server:
        readProtector = try pair.withClientSecret {
          secret throws(DTLS13RecordError) in
          try RFC9147DTLS13RecordProtector(
            cipherSuite: pair.cipherSuite,
            trafficSecret: secret,
            epoch: numericEpoch,
            connectionID: sourceConnectionID.isEmpty ? nil : sourceConnectionID.span
          )
        }
        writeProtector = try pair.withServerSecret {
          secret throws(DTLS13RecordError) in
          try RFC9147DTLS13RecordProtector(
            cipherSuite: pair.cipherSuite,
            trafficSecret: secret,
            epoch: numericEpoch,
            connectionID: destinationConnectionID.isEmpty ? nil : destinationConnectionID.span
          )
        }
      }
    } catch let error as DTLS13RecordError {
      throw .record(error)
    } catch {
      throw .invalidState
    }
    guard let installedReadProtector = readProtector.take(),
      let installedWriteProtector = writeProtector.take()
    else {
      throw .invalidState
    }
    switch epoch {
    case .initial, .earlyData:
      throw .invalidState
    case .handshake:
      guard handshakeRead == nil, handshakeWrite == nil else {
        throw .invalidState
      }
      handshakeRead = consume installedReadProtector
      handshakeWrite = consume installedWriteProtector
    case .application:
      guard applicationRead == nil, applicationWrite == nil else {
        throw .invalidState
      }
      applicationRead = consume installedReadProtector
      applicationWrite = consume installedWriteProtector
    }
  }
}
import SSLTypes
