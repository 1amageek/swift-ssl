public enum PBKDF2Error: Error, Sendable, Equatable {
  case invalidIterationCount(UInt32)
  case invalidOutputLength(Int)
  case outputTooLong(limit: UInt64, actual: Int)
  case overlappingInputAndOutput
  case primitiveFailure(CryptoInputError)
}
