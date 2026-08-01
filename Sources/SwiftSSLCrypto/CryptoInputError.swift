import SwiftSSLCore

public enum CryptoInputError: Error, Sendable, Equatable {
  case invalidLength(expected: Int, actual: Int)
  case invalidOutputLength(expected: Int, actual: Int)
  case nonCanonicalEncoding
  case contextTooLong(limit: Int, actual: Int)
  case inputTooLong(limit: UInt64)
  case invalidPeerKey
  case invalidSignature
}
