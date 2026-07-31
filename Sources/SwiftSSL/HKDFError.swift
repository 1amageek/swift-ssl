import SwiftSSLCrypto

public enum HKDFError: Error, Sendable, Equatable {
  case pseudorandomKeyTooShort(minimum: Int, actual: Int)
  case invalidPseudorandomKeyOutputLength(expected: Int, actual: Int)
  case outputTooLong(limit: Int, actual: Int)
  case inputTooLong(limit: UInt64)
  case overlappingInputAndOutput
  case primitiveFailure(CryptoInputError)

  init(_ error: SwiftSSLCrypto.HKDFError) {
    switch error {
    case .pseudorandomKeyTooShort(let minimum, let actual):
      self = .pseudorandomKeyTooShort(
        minimum: minimum,
        actual: actual
      )
    case .invalidPseudorandomKeyOutputLength(let expected, let actual):
      self = .invalidPseudorandomKeyOutputLength(
        expected: expected,
        actual: actual
      )
    case .outputTooLong(let limit, let actual):
      self = .outputTooLong(limit: limit, actual: actual)
    case .inputTooLong(let limit):
      self = .inputTooLong(limit: limit)
    case .overlappingInputAndOutput:
      self = .overlappingInputAndOutput
    case .primitiveFailure(let primitiveError):
      self = .primitiveFailure(CryptoInputError(primitiveError))
    }
  }
}
