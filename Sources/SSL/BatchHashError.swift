import SSLCrypto

public enum BatchHashError: Error, Sendable, Equatable {
  case invalidInputRange(index: Int)
  case inputTooLong(index: Int, limit: UInt64)
  case outputLengthOverflow
  case invalidOutputLength(expected: Int, actual: Int)
  case overlappingInputAndOutput
  case primitiveFailure(index: Int, error: CryptoInputError)

  init(_ error: SSLCrypto.BatchHashError) {
    switch error {
    case .invalidInputRange(let index):
      self = .invalidInputRange(index: index)
    case .inputTooLong(let index, let limit):
      self = .inputTooLong(index: index, limit: limit)
    case .outputLengthOverflow:
      self = .outputLengthOverflow
    case .invalidOutputLength(let expected, let actual):
      self = .invalidOutputLength(expected: expected, actual: actual)
    case .overlappingInputAndOutput:
      self = .overlappingInputAndOutput
    case .primitiveFailure(let index, let primitiveError):
      self = .primitiveFailure(
        index: index,
        error: CryptoInputError(primitiveError)
      )
    }
  }
}
