import SSLCore

/// One raw key-share offer from a TLS 1.3 ClientHello.
///
/// The group identifier remains raw at the wire boundary so unknown and
/// GREASE groups can coexist with groups implemented by this package.
public struct TLS13ClientKeyShare: Sendable, Hashable {
  public let groupID: UInt16
  public let keyExchange: OwnedBytes

  public init(groupID: UInt16, keyExchange: consuming OwnedBytes) {
    self.groupID = groupID
    self.keyExchange = keyExchange
  }
}
