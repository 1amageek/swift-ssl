import SSLCore

public enum DTLS13ConnectionError: Error, Sendable, Equatable {
  case invalidConfiguration
  case invalidState
  case keyUpdateAlreadyPending
  case keyUpdateRequiresHandshakeConfirmation
  case applicationEpochExhausted
  case cookie(DTLS13CookieError)
  case malformedDatagram
  case unexpectedEpoch(UInt8)
  case handshake(TLS13HandshakeEngineError)
  case record(DTLS13RecordError)
  case fragment(DTLS13HandshakeFragmentError)
  case acknowledgment(DTLS13AcknowledgmentError)
  case flight(DTLS13FlightError)
  case output(ByteError)
}
