import SwiftSSLCore

public enum SecretMemoryError: Error, Sendable, Equatable {
  case invalidByteCount(Int)
  case byteCountExceedsLimit(limit: Int, actual: Int)

  init(_ error: SwiftSSLCore.SecretMemoryError) {
    switch error {
    case .invalidByteCount(let count):
      self = .invalidByteCount(count)
    case .byteCountExceedsLimit(let limit, let actual):
      self = .byteCountExceedsLimit(limit: limit, actual: actual)
    }
  }
}
