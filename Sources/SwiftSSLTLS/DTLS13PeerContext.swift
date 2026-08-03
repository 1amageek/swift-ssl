import SwiftSSLCore

/// Authenticated input used to bind a DTLS cookie to one transport peer.
///
/// `identity` is an opaque, canonical transport address encoding supplied by
/// the datagram adapter. It must distinguish peers whose cookies must not be
/// interchangeable. `receivedAt` is captured once for the received datagram.
public struct DTLS13PeerContext: Sendable, Hashable {
  public let identity: OwnedBytes
  public let receivedAt: VerificationInstant

  public init(
    identity: Span<UInt8>,
    receivedAt: VerificationInstant
  ) throws(DTLS13CookieError) {
    guard !identity.isEmpty, identity.count <= UInt16.max else {
      throw .invalidConfiguration
    }
    self.identity = OwnedBytes(copying: identity)
    self.receivedAt = receivedAt
  }
}
