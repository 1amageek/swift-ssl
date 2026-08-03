import SSLCore

public enum DTLS13AcknowledgmentError: Error, Sendable, Equatable {
  case byte(ByteError)
  case malformedLength(Int)
  case recordNumbersNotStrictlyIncreasing
  case record(DTLS13RecordError)
}
