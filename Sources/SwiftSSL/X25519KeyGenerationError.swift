import SwiftSSLCore

public enum X25519KeyGenerationError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case memoryFailure
}
