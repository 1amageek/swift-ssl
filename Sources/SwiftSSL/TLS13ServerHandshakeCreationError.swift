import SwiftSSLCore
import SwiftSSLTLS

/// Failures produced while composing a TLS 1.3 server handshake.
public enum TLS13ServerHandshakeCreationError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case clock(ClockError)
  case keyExchange(TLS13KeyExchangeError)
  case handshake(TLS13HandshakeEngineError)
}
