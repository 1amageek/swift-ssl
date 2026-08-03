import SSLCore

/// One datagram range and the handshake record numbers carried by it.
public struct DTLS13FlightDatagram: Sendable, Hashable {
  public let bytes: ByteRange
  public let recordNumbers: ContiguousArray<DTLS13RecordNumber>

  public init(
    bytes: ByteRange,
    recordNumbers: consuming ContiguousArray<DTLS13RecordNumber>
  ) throws(DTLS13FlightError) {
    guard !recordNumbers.isEmpty else { throw .datagramHasNoHandshakeRecords }
    self.bytes = bytes
    self.recordNumbers = recordNumbers
  }
}
