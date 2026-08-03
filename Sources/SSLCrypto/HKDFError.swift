public enum HKDFError: Error, Sendable, Equatable {
  case pseudorandomKeyTooShort(minimum: Int, actual: Int)
  case invalidPseudorandomKeyOutputLength(expected: Int, actual: Int)
  case outputTooLong(limit: Int, actual: Int)
  case inputTooLong(limit: UInt64)
  case overlappingInputAndOutput
  case primitiveFailure(CryptoInputError)
}
