import SwiftSSLCore

/// An owned ALPN protocol identifier.
public struct TLS13ApplicationProtocol: Sendable, Hashable {
  private let identifier: OwnedBytes

  public init(
    identifier: Span<UInt8>
  ) throws(TLS13ApplicationProtocolError) {
    guard !identifier.isEmpty, identifier.count <= UInt8.max else {
      throw .invalidIdentifierLength(actual: identifier.count)
    }
    self.identifier = OwnedBytes(copying: identifier)
  }

  public var byteCount: Int { identifier.count }

  public borrowing func withIdentifierBytes<Result, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(identifier.span)
  }
}
