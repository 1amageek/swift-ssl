import SwiftSSLCore

/// The public wire ClientHello and private transcript ClientHello for one ECH offer.
public struct ECHClientHelloOffer: Sendable, Hashable {
  public let outerClientHello: OwnedBytes
  public let innerClientHello: OwnedBytes

  public init(
    outerClientHello: consuming OwnedBytes,
    innerClientHello: consuming OwnedBytes
  ) {
    self.outerClientHello = outerClientHello
    self.innerClientHello = innerClientHello
  }
}
