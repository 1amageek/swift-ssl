/// The peer whose authentication material is being processed.
public enum TLS13PeerRole: UInt8, Sendable, Hashable {
  case client
  case server
}
