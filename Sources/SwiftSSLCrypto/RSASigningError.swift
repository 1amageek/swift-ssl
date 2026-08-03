import SwiftSSLCore

public enum RSASigningError: Error, Sendable, Equatable {
  case crypto(CryptoInputError)
  case entropy(EntropyError)
  case selfCheckFailed
}
