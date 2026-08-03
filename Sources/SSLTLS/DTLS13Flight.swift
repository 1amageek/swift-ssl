import SSLCore

/// An immutable flight owner shared by initial transmission and retransmits.
public struct DTLS13Flight: Sendable, Hashable {
  public let bytes: OwnedBytes
  public let datagrams: ContiguousArray<DTLS13FlightDatagram>
  public let isFinalFlight: Bool

  public init(
    bytes: consuming OwnedBytes,
    datagrams: consuming ContiguousArray<DTLS13FlightDatagram>,
    isFinalFlight: Bool
  ) throws(DTLS13FlightError) {
    self.bytes = bytes
    self.datagrams = datagrams
    self.isFinalFlight = isFinalFlight
    guard !self.datagrams.isEmpty else { throw .emptyFlight }
    var knownRecordNumbers = Set<DTLS13RecordNumber>()
    for datagram in self.datagrams {
      guard self.bytes.contains(datagram.bytes) else {
        throw .byteRangeOutsideFlight(datagram.bytes)
      }
      for recordNumber in datagram.recordNumbers {
        guard knownRecordNumbers.insert(recordNumber).inserted else {
          throw .duplicateRecordNumber(recordNumber)
        }
      }
    }
  }
}
