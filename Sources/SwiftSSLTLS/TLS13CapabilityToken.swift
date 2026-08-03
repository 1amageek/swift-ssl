import SwiftSSLCore

/// Correlates exactly one external capability response with one engine.
public struct TLS13CapabilityToken: Sendable, Hashable {
  public let engineIdentifier: OwnedBytes
  public let sequence: UInt64
  public let kind: TLS13CapabilityKind

  package init(
    engineIdentifier: OwnedBytes,
    sequence: UInt64,
    kind: TLS13CapabilityKind
  ) {
    self.engineIdentifier = engineIdentifier
    self.sequence = sequence
    self.kind = kind
  }
}
