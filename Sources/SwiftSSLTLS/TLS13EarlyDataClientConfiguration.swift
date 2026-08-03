/// Explicit client authorization to send replayable TLS 1.3 early data.
public struct TLS13EarlyDataClientConfiguration: Sendable, Hashable {
  public let maximumByteCount: UInt32

  public init(
    maximumByteCount: UInt32
  ) throws(TLS13EarlyDataConfigurationError) {
    guard maximumByteCount > 0 else { throw .invalidMaximumByteCount }
    self.maximumByteCount = maximumByteCount
  }
}
