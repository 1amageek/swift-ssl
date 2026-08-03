import SSLCore
import SSLCrypto

/// One owned client-to-server TLS 1.3 early traffic secret.
///
/// Unlike handshake and application traffic secrets, 0-RTT has no server
/// sending secret. The value therefore remains a distinct noncopyable owner
/// instead of manufacturing an invalid pair.
public struct TLS13EarlyTrafficSecret: ~Copyable, Sendable {
  public let cipherSuite: TLSCipherSuite
  private let secret: SecretBytes

  package init(
    cipherSuite: TLSCipherSuite,
    secret: consuming SecretBytes
  ) {
    self.cipherSuite = cipherSuite
    self.secret = consume secret
  }

  public borrowing func withBorrowedSecret<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try secret.withBorrowedBytes(body)
  }

  package consuming func takeSecret() -> SecretBytes {
    secret
  }
}
