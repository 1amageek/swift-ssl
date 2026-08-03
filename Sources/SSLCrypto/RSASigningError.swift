import SSLCore

public enum RSASigningError: Error, Sendable, Equatable {
  case crypto(CryptoInputError)
  case entropy(EntropyError)
  case selfCheckFailed
}
