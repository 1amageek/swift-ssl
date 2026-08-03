/// Observable state of one explicitly requested TLS 1.3 0-RTT attempt.
public enum TLS13EarlyDataState: Sendable, Hashable {
  case notRequested
  case offered
  case accepted
  case rejected
}
