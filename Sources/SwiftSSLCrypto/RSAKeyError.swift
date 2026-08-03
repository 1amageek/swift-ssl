import SwiftSSLCore

public enum RSAKeyError: Error, Sendable, Equatable {
  case crypto(CryptoInputError)
  case secretMemory(SecretMemoryError)
  case invalidKeyRelation
}
