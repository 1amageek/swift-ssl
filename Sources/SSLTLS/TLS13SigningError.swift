import SSLCrypto

public enum TLS13SigningError: Error, Sendable, Equatable {
  case crypto(CryptoInputError)
  case rsa(RSASigningError)
}
