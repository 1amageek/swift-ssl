/// Server limits and replay authorization for TLS 1.3 early data.
public struct TLS13EarlyDataServerConfiguration: Sendable {
  public let maximumByteCount: UInt32
  package let replayProtector: any TLS13EarlyDataReplayProtecting

  public init(
    maximumByteCount: UInt32,
    replayProtector: any TLS13EarlyDataReplayProtecting
  ) throws(TLS13EarlyDataConfigurationError) {
    guard maximumByteCount > 0 else { throw .invalidMaximumByteCount }
    self.maximumByteCount = maximumByteCount
    self.replayProtector = replayProtector
  }
}
