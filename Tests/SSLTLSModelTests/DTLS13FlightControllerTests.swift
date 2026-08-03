import SSLCore
import SSLTLS
import XCTest

final class DTLS13FlightControllerTests: XCTestCase {
  func testSelectiveAcknowledgmentRetransmitsOnlyMissingDatagram() throws {
    let record0 = try DTLS13RecordNumber(epoch: 2, sequenceNumber: 0)
    let record1 = try DTLS13RecordNumber(epoch: 2, sequenceNumber: 1)
    let flightBytes: ContiguousArray<UInt8> = [10, 11, 20, 21]
    let flight = try DTLS13Flight(
      bytes: OwnedBytes(copying: flightBytes.span),
      datagrams: [
        try DTLS13FlightDatagram(
          bytes: try ByteRange(offset: 0, count: 2),
          recordNumbers: [record0]
        ),
        try DTLS13FlightDatagram(
          bytes: try ByteRange(offset: 2, count: 2),
          recordNumbers: [record1]
        ),
      ],
      isFinalFlight: false
    )
    var controller = try RFC9147DTLS13FlightController()
    let initial = try controller.startFlight(flight)
    XCTAssertEqual(initial.actions.count, 4)
    XCTAssertEqual(initial.actions[0], .emitDatagram(try ByteRange(offset: 0, count: 2)))
    XCTAssertEqual(initial.actions[1], .emitDatagram(try ByteRange(offset: 2, count: 2)))
    XCTAssertEqual(initial.actions[2], .flushFlight)
    XCTAssertEqual(initial.actions[3], .scheduleRetransmission(afterMilliseconds: 1_000))

    let partial = try controller.receiveAcknowledgment(
      try DTLS13Acknowledgment(recordNumbers: [record0])
    )
    XCTAssertEqual(partial.actions.count, 3)
    XCTAssertEqual(partial.actions[0], .emitDatagram(try ByteRange(offset: 2, count: 2)))
    XCTAssertEqual(partial.actions[1], .flushFlight)
    XCTAssertEqual(partial.actions[2], .scheduleRetransmission(afterMilliseconds: 2_000))
  }

  func testCompleteFinalFlightAcknowledgmentCancelsTimerAndConfirms() throws {
    let record = try DTLS13RecordNumber(epoch: 2, sequenceNumber: 0)
    let bytes: ContiguousArray<UInt8> = [1]
    let flight = try DTLS13Flight(
      bytes: OwnedBytes(copying: bytes.span),
      datagrams: [
        try DTLS13FlightDatagram(
          bytes: try ByteRange(offset: 0, count: 1),
          recordNumbers: [record]
        )
      ],
      isFinalFlight: true
    )
    var controller = try RFC9147DTLS13FlightController()
    _ = try controller.startFlight(flight)
    let completed = try controller.receiveAcknowledgment(
      try DTLS13Acknowledgment(recordNumbers: [record])
    )
    XCTAssertEqual(completed.actions, [.cancelRetransmission, .handshakeConfirmed])
    XCTAssertFalse(controller.hasOutstandingFlight)
  }

  func testTimerUsesBoundedExponentialBackoff() throws {
    let record = try DTLS13RecordNumber(epoch: 0, sequenceNumber: 0)
    let bytes: ContiguousArray<UInt8> = [1]
    let flight = try DTLS13Flight(
      bytes: OwnedBytes(copying: bytes.span),
      datagrams: [
        try DTLS13FlightDatagram(
          bytes: try ByteRange(offset: 0, count: 1),
          recordNumbers: [record]
        )
      ],
      isFinalFlight: false
    )
    var controller = try RFC9147DTLS13FlightController(
      initialTimeoutMilliseconds: 40_000,
      maximumTimeoutMilliseconds: 60_000
    )
    _ = try controller.startFlight(flight)
    let retransmit = try controller.retransmissionTimerExpired()
    XCTAssertEqual(
      retransmit.actions.last,
      .scheduleRetransmission(afterMilliseconds: 60_000)
    )
  }
}
