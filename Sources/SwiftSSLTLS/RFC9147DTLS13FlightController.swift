import SwiftSSLCore

/// RFC 9147 flight retransmission state with selective ACK suppression.
///
/// The controller owns one immutable byte backing for the complete flight.
/// Every retransmission returns the same COW backing and emits only ranges for
/// datagrams that still contain an unacknowledged handshake record.
public struct RFC9147DTLS13FlightController: DTLS13FlightControlling, Sendable {
  public static let defaultInitialTimeoutMilliseconds: UInt64 = 1_000
  public static let defaultMaximumTimeoutMilliseconds: UInt64 = 60_000
  public static let defaultMaximumRetransmissionCount = 12

  public private(set) var retransmissionCount: Int

  private let initialTimeoutMilliseconds: UInt64
  private let maximumTimeoutMilliseconds: UInt64
  private let maximumRetransmissionCount: Int
  private var currentTimeoutMilliseconds: UInt64
  private var flight: DTLS13Flight?
  private var acknowledgedRecordNumbers: Set<DTLS13RecordNumber>

  public init(
    initialTimeoutMilliseconds: UInt64 = Self.defaultInitialTimeoutMilliseconds,
    maximumTimeoutMilliseconds: UInt64 = Self.defaultMaximumTimeoutMilliseconds,
    maximumRetransmissionCount: Int = Self.defaultMaximumRetransmissionCount
  ) throws(DTLS13FlightError) {
    guard initialTimeoutMilliseconds > 0,
      maximumTimeoutMilliseconds >= initialTimeoutMilliseconds,
      maximumRetransmissionCount > 0
    else {
      throw .invalidTimeoutConfiguration
    }
    self.initialTimeoutMilliseconds = initialTimeoutMilliseconds
    self.maximumTimeoutMilliseconds = maximumTimeoutMilliseconds
    self.maximumRetransmissionCount = maximumRetransmissionCount
    currentTimeoutMilliseconds = initialTimeoutMilliseconds
    retransmissionCount = 0
    flight = nil
    acknowledgedRecordNumbers = []
  }

  public var hasOutstandingFlight: Bool { flight != nil }

  public mutating func startFlight(
    _ flight: consuming DTLS13Flight
  ) throws(DTLS13FlightError) -> DTLSActionBatch {
    guard self.flight == nil else { throw .flightAlreadyOutstanding }
    self.flight = flight
    acknowledgedRecordNumbers.removeAll(keepingCapacity: true)
    currentTimeoutMilliseconds = initialTimeoutMilliseconds
    retransmissionCount = 0
    return try makeTransmissionBatch(scheduleTimer: true)
  }

  public mutating func receiveAcknowledgment(
    _ acknowledgment: DTLS13Acknowledgment
  ) throws(DTLS13FlightError) -> DTLSActionBatch {
    guard let flight else { return try emptyBatch() }
    let currentRecordNumbers = Self.recordNumbers(in: flight)
    var acceptedNewAcknowledgment = false
    for recordNumber in acknowledgment.recordNumbers where currentRecordNumbers.contains(recordNumber) {
      if acknowledgedRecordNumbers.insert(recordNumber).inserted {
        acceptedNewAcknowledgment = true
      }
    }
    guard !allRecordsAcknowledged(in: flight) else {
      let isFinalFlight = flight.isFinalFlight
      self.flight = nil
      var actions: ContiguousArray<DTLSAction> = [.cancelRetransmission]
      if isFinalFlight {
        actions.append(.handshakeConfirmed)
      }
      return try makeBatch(bytes: OwnedBytes(), actions: actions)
    }
    guard acceptedNewAcknowledgment else {
      return try emptyBatch()
    }
    guard retransmissionCount < maximumRetransmissionCount else {
      throw .retransmissionLimitReached(limit: maximumRetransmissionCount)
    }
    advanceTimeout()
    retransmissionCount += 1
    return try makeTransmissionBatch(scheduleTimer: true)
  }

  public mutating func receiveImplicitAcknowledgment()
    throws(DTLS13FlightError) -> DTLSActionBatch {
    guard flight != nil else { return try emptyBatch() }
    flight = nil
    acknowledgedRecordNumbers.removeAll(keepingCapacity: true)
    return try makeBatch(
      bytes: OwnedBytes(),
      actions: [.cancelRetransmission]
    )
  }

  public mutating func retransmissionTimerExpired()
    throws(DTLS13FlightError) -> DTLSActionBatch {
    guard flight != nil else { throw .noOutstandingFlight }
    guard retransmissionCount < maximumRetransmissionCount else {
      throw .retransmissionLimitReached(limit: maximumRetransmissionCount)
    }
    retransmissionCount += 1
    advanceTimeout()
    return try makeTransmissionBatch(scheduleTimer: true)
  }

  private mutating func makeTransmissionBatch(
    scheduleTimer: Bool
  ) throws(DTLS13FlightError) -> DTLSActionBatch {
    guard let flight else { throw .noOutstandingFlight }
    var actions = ContiguousArray<DTLSAction>()
    for datagram in flight.datagrams {
      var containsUnacknowledgedRecord = false
      for recordNumber in datagram.recordNumbers
      where !acknowledgedRecordNumbers.contains(recordNumber) {
        containsUnacknowledgedRecord = true
        break
      }
      if containsUnacknowledgedRecord {
        actions.append(.emitDatagram(datagram.bytes))
      }
    }
    actions.append(.flushFlight)
    if scheduleTimer {
      actions.append(
        .scheduleRetransmission(afterMilliseconds: currentTimeoutMilliseconds)
      )
    }
    return try makeBatch(bytes: flight.bytes, actions: actions)
  }

  private func allRecordsAcknowledged(in flight: DTLS13Flight) -> Bool {
    for datagram in flight.datagrams {
      for recordNumber in datagram.recordNumbers
      where !acknowledgedRecordNumbers.contains(recordNumber) {
        return false
      }
    }
    return true
  }

  private mutating func advanceTimeout() {
    let (doubled, overflow) = currentTimeoutMilliseconds.multipliedReportingOverflow(by: 2)
    currentTimeoutMilliseconds = overflow
      ? maximumTimeoutMilliseconds
      : Swift.min(doubled, maximumTimeoutMilliseconds)
  }

  private static func recordNumbers(
    in flight: DTLS13Flight
  ) -> Set<DTLS13RecordNumber> {
    var result = Set<DTLS13RecordNumber>()
    for datagram in flight.datagrams {
      result.formUnion(datagram.recordNumbers)
    }
    return result
  }

  private func emptyBatch() throws(DTLS13FlightError) -> DTLSActionBatch {
    try makeBatch(bytes: OwnedBytes(), actions: [])
  }

  private func makeBatch(
    bytes: consuming OwnedBytes,
    actions: consuming ContiguousArray<DTLSAction>
  ) throws(DTLS13FlightError) -> DTLSActionBatch {
    do {
      return try DTLSActionBatch(bytes: bytes, actions: actions)
    } catch let error {
      throw .output(error)
    }
  }
}
