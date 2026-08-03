import SSLCore

public enum DTLS13FlightError: Error, Sendable, Equatable {
  case invalidTimeoutConfiguration
  case emptyFlight
  case datagramHasNoHandshakeRecords
  case byteRangeOutsideFlight(ByteRange)
  case duplicateRecordNumber(DTLS13RecordNumber)
  case flightAlreadyOutstanding
  case noOutstandingFlight
  case retransmissionLimitReached(limit: Int)
  case output(ByteError)
}
