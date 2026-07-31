import SwiftSSLCrypto

public enum AEADError: Error, Sendable, Equatable {
  case invalidKeyLength(expected: [Int], actual: Int)
  case invalidNonceLength(expected: Int, actual: Int)
  case outputTooSmall(required: Int, actual: Int)
  case overlappingInputAndOutput
  case authenticationFailed
  case messageLimitReached

  init(_ error: SwiftSSLCrypto.AEADError) {
    switch error {
    case .invalidKeyLength(let expected, let actual):
      self = .invalidKeyLength(expected: expected, actual: actual)
    case .invalidNonceLength(let expected, let actual):
      self = .invalidNonceLength(expected: expected, actual: actual)
    case .outputTooSmall(let required, let actual):
      self = .outputTooSmall(required: required, actual: actual)
    case .overlappingInputAndOutput:
      self = .overlappingInputAndOutput
    case .authenticationFailed:
      self = .authenticationFailed
    case .messageLimitReached:
      self = .messageLimitReached
    }
  }
}
