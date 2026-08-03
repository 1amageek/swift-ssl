import SSLTLS
import XCTest

final class DTLS13AcknowledgmentTests: XCTestCase {
  func testRoundTripsRecordNumbers() throws {
    let acknowledgment = try DTLS13Acknowledgment(
      recordNumbers: [
        try DTLS13RecordNumber(epoch: 2, sequenceNumber: 3),
        try DTLS13RecordNumber(epoch: 3, sequenceNumber: 0),
      ]
    )
    let codec = RFC9147DTLS13AcknowledgmentCodec()
    let encoded = try codec.encode(acknowledgment)
    let decoded = try codec.parse(encoded.span)
    XCTAssertEqual(decoded, acknowledgment)
  }

  func testAllowsEmptyAcknowledgment() throws {
    let acknowledgment = try DTLS13Acknowledgment(recordNumbers: [])
    let codec = RFC9147DTLS13AcknowledgmentCodec()
    let encoded = try codec.encode(acknowledgment)
    XCTAssertEqual(try codec.parse(encoded.span), acknowledgment)
  }

  func testRejectsUnsortedRecordNumbers() throws {
    XCTAssertThrowsError(
      try DTLS13Acknowledgment(
        recordNumbers: [
          try DTLS13RecordNumber(epoch: 2, sequenceNumber: 4),
          try DTLS13RecordNumber(epoch: 2, sequenceNumber: 3),
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? DTLS13AcknowledgmentError,
        .recordNumbersNotStrictlyIncreasing
      )
    }
  }
}
