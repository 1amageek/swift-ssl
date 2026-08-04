import SSLCrypto

public enum CryptoInputError: Error, Sendable, Equatable {
  case invalidLength(expected: Int, actual: Int)
  case invalidOutputLength(expected: Int, actual: Int)
  case nonCanonicalEncoding
  case contextTooLong(limit: Int, actual: Int)
  case inputTooLong(limit: UInt64)
  case invalidPeerKey
  case invalidSignature
  case invalidRange

  init(_ error: SSLCrypto.CryptoInputError) {
    switch error {
    case .invalidLength(let expected, let actual):
      self = .invalidLength(expected: expected, actual: actual)
    case .invalidOutputLength(let expected, let actual):
      self = .invalidOutputLength(expected: expected, actual: actual)
    case .nonCanonicalEncoding:
      self = .nonCanonicalEncoding
    case .contextTooLong(let limit, let actual):
      self = .contextTooLong(limit: limit, actual: actual)
    case .inputTooLong(let limit):
      self = .inputTooLong(limit: limit)
    case .invalidPeerKey:
      self = .invalidPeerKey
    case .invalidSignature:
      self = .invalidSignature
    case .invalidRange:
      self = .invalidRange
    }
  }
}
