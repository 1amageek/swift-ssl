import SwiftSSLCore

public enum P256KeyGenerationError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case invalidScalar
}
