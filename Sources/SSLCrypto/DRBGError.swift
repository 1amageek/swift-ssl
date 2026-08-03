import SSLCore

public enum DRBGError: Error, Sendable, Equatable {
  case entropy(EntropyError)
  case inputTooLarge(limit: Int, actual: Int)
  case outputTooLarge(limit: Int, actual: Int)
  case reseedRequired
  case cryptographicFailure(CryptoInputError)
}
