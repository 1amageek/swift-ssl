public enum DTLS13RecordContentType: UInt8, Sendable, Hashable {
  case alert = 21
  case handshake = 22
  case applicationData = 23
  case acknowledgment = 26
}
