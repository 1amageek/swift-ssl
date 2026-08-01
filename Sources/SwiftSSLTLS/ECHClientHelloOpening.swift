import SwiftSSLCore

/// Opens and validates one RFC 9849 ClientHelloOuter.
public protocol ECHClientHelloOpening: ~Copyable, Sendable {
  mutating func open(
    _ outerClientHello: Span<UInt8>
  ) throws(ECHError) -> ECHOpenedClientHello
}
