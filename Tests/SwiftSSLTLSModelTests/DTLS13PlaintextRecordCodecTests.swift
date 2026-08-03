import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class DTLS13PlaintextRecordCodecTests: XCTestCase {
  func testRoundTripsMultipleRecordsWithoutMaterializingPayloads() throws {
    let codec = RFC9147DTLS13PlaintextRecordCodec()
    let first: ContiguousArray<UInt8> = [1, 2, 3]
    let second: ContiguousArray<UInt8> = [4, 5]
    var datagram = ContiguousArray<UInt8>()
    try codec.appendRecord(
      contentType: .handshake,
      sequenceNumber: 7,
      fragment: first.span,
      to: &datagram
    )
    try codec.appendRecord(
      contentType: .acknowledgment,
      sequenceNumber: 8,
      fragment: second.span,
      to: &datagram
    )

    let records = try codec.records(in: datagram.span)
    XCTAssertEqual(records.count, 2)
    XCTAssertEqual(records[0].recordNumber.sequenceNumber, 7)
    XCTAssertEqual(records[1].contentType, .acknowledgment)
    XCTAssertEqual(
      OwnedBytes(
        copying: datagram.span.extracting(
          records[0].fragment.offset..<records[0].fragment.endOffset
        )
      ),
      OwnedBytes(copying: first.span)
    )
    XCTAssertEqual(
      OwnedBytes(
        copying: datagram.span.extracting(
          records[1].fragment.offset..<records[1].fragment.endOffset
        )
      ),
      OwnedBytes(copying: second.span)
    )
  }

  func testRejectsTruncatedRecord() throws {
    let codec = RFC9147DTLS13PlaintextRecordCodec()
    let bytes: ContiguousArray<UInt8> = [22, 0xFE, 0xFD, 0, 0]
    XCTAssertThrowsError(try codec.records(in: bytes.span))
  }
}
