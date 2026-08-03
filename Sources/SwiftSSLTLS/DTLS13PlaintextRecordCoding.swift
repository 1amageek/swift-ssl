import SwiftSSLCore

public protocol DTLS13PlaintextRecordCoding: Sendable {
  func records(
    in datagram: Span<UInt8>
  ) throws(DTLS13RecordError) -> ContiguousArray<DTLS13PlaintextRecord>

  func appendRecord(
    contentType: DTLS13RecordContentType,
    sequenceNumber: UInt64,
    fragment: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) throws(DTLS13RecordError)
}
