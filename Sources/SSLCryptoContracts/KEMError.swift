
public enum KEMError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case primitiveFailure(CryptoInputError)
  case secretMemory(SecretMemoryError)
  case invalidPublicKeyLength(expected: Int, actual: Int)
  case invalidPublicKeyEncoding
  case invalidPrivateKeyLength(expected: Int, actual: Int)
  case invalidPrivateKeyEncoding
  case invalidEncapsulationLength(expected: Int, actual: Int)
  case invalidSharedSecretLength(expected: Int, actual: Int)
}
