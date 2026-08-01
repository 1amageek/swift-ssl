/// A NewSessionTicket wire output paired with the server state required to
/// accept that ticket exactly once.
///
/// The wire bytes are copyable owned output. The resumption state remains a
/// move-only value and must be consumed into the application's ticket store.
public struct TLS13IssuedSessionTicket: ~Copyable, Sendable {
  public let output: TLS13HandshakeOutput

  private let resumptionState: TLS13ResumptionState

  package init(
    output: consuming TLS13HandshakeOutput,
    resumptionState: consuming TLS13ResumptionState
  ) {
    self.output = output
    self.resumptionState = resumptionState
  }

  public consuming func takeResumptionState() -> TLS13ResumptionState {
    consume resumptionState
  }
}
