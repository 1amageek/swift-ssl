/// Atomically authorizes or rejects one authenticated early-data attempt.
///
/// Implementations must persist or otherwise coordinate acceptance strongly
/// enough for their replay threat model before returning `.accept`.
public protocol TLS13EarlyDataReplayProtecting: Sendable {
  func evaluate(
    _ context: TLS13EarlyDataReplayContext
  ) throws -> TLS13EarlyDataReplayDecision
}
