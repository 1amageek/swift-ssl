import SwiftSSLCore

/// An authenticated ClientHelloInner reconstructed from ClientHelloOuter.
public struct ECHOpenedClientHello: Sendable, Hashable {
  public let innerClientHello: OwnedBytes
  public let configID: UInt8
  public let cipherSuite: ECHCipherSuite

  public init(
    innerClientHello: consuming OwnedBytes,
    configID: UInt8,
    cipherSuite: ECHCipherSuite
  ) {
    self.innerClientHello = innerClientHello
    self.configID = configID
    self.cipherSuite = cipherSuite
  }
}
