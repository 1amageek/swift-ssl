import SwiftSSLCore

public protocol DTLS13DatagramRecordFraming: Sendable {
  func records(
    in datagram: Span<UInt8>
  ) throws(DTLS13RecordError) -> ContiguousArray<DTLS13DatagramRecord>
}
