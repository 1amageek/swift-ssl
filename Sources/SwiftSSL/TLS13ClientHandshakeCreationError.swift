import SwiftSSLCore
import SwiftSSLTLS

/// Failures produced while composing a TLS 1.3 client handshake.
public enum TLS13ClientHandshakeCreationError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case clock(ClockError)
  case keyExchange(TLS13KeyExchangeError)
  case handshake(TLS13HandshakeEngineError)
}
