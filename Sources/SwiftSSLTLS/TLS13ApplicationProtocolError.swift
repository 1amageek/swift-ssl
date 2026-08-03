public enum TLS13ApplicationProtocolError: Error, Sendable, Equatable {
  case invalidIdentifierLength(actual: Int)
  case duplicateIdentifier
  case noApplicationProtocol
}
