import SSLCore

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
}
