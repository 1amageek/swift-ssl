import SwiftSSLCore

/// Stateful RFC 9849 ClientHello sealing with one monotonic HPKE sequence.
public protocol ECHClientHelloSealing: ~Copyable, Sendable {
  mutating func seal(
    innerClientHello: Span<UInt8>,
    outerClientHello: Span<UInt8>
  ) throws(ECHError) -> ECHClientHelloOffer
}
