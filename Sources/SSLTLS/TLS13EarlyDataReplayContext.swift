import SSLCore

/// Authenticated ticket metadata presented to a server replay policy.
public struct TLS13EarlyDataReplayContext: Sendable, Hashable {
  public let ticketIdentity: OwnedBytes
  public let obfuscatedTicketAge: UInt32
  public let applicationProtocol: TLS13ApplicationProtocol?

  package init(
    ticketIdentity: Span<UInt8>,
    obfuscatedTicketAge: UInt32,
    applicationProtocol: TLS13ApplicationProtocol?
  ) {
    self.ticketIdentity = OwnedBytes(copying: ticketIdentity)
    self.obfuscatedTicketAge = obfuscatedTicketAge
    self.applicationProtocol = applicationProtocol
  }
}
