import SwiftSSLCrypto

public enum MLDSAError: Error, Equatable, Sendable {
  case invalidSeedLength(expected: Int, actual: Int)
  case invalidPublicKeyLength(expected: Int, actual: Int)
  case invalidPrivateKeyLength(expected: Int, actual: Int)
  case invalidSignatureLength(expected: Int, actual: Int)
  case invalidSignatureOutputLength(expected: Int, actual: Int)
  case invalidPrivateKeyEncoding
  case contextTooLong(limit: Int, actual: Int)
  case inputTooLong
  case entropy(EntropyError)
  case secretMemory(SecretMemoryError)

  init(_ error: SwiftSSLCrypto.MLDSAError) {
    switch error {
    case .invalidSeedLength(let expected, let actual):
      self = .invalidSeedLength(expected: expected, actual: actual)
    case .invalidPublicKeyLength(let expected, let actual):
      self = .invalidPublicKeyLength(expected: expected, actual: actual)
    case .invalidPrivateKeyLength(let expected, let actual):
      self = .invalidPrivateKeyLength(expected: expected, actual: actual)
    case .invalidSignatureLength(let expected, let actual):
      self = .invalidSignatureLength(expected: expected, actual: actual)
    case .invalidSignatureOutputLength(let expected, let actual):
      self = .invalidSignatureOutputLength(expected: expected, actual: actual)
    case .invalidPrivateKeyEncoding:
      self = .invalidPrivateKeyEncoding
    case .contextTooLong(let limit, let actual):
      self = .contextTooLong(limit: limit, actual: actual)
    case .inputTooLong:
      self = .inputTooLong
    case .entropy(let error):
      self = .entropy(error)
    case .secretMemory(let error):
      self = .secretMemory(SecretMemoryError(error))
    }
  }
}
