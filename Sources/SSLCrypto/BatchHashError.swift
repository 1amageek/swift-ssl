public enum BatchHashError: Error, Sendable, Equatable {
  case invalidInputRange(index: Int)
  case inputTooLong(index: Int, limit: UInt64)
  case outputLengthOverflow
  case invalidOutputLength(expected: Int, actual: Int)
  case overlappingInputAndOutput
  case primitiveFailure(index: Int, error: CryptoInputError)
}
