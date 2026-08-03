/// Selects when a server requests TLS 1.3 client authentication.
public enum TLS13ClientAuthenticationTiming: Sendable, Hashable {
  case mainHandshake
  case postHandshake
  case mainAndPostHandshake

  package var includesMainHandshake: Bool {
    self != .postHandshake
  }

  package var includesPostHandshake: Bool {
    self != .mainHandshake
  }
}
