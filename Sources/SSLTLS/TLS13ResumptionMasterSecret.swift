import SSLCore
import SSLCrypto

/// A TLS 1.3 resumption master secret derived from the transcript through
/// Client Finished.
///
/// This owner is separate from application traffic secrets because RFC 8446
/// assigns them different transcript boundaries. The secret is never exposed
/// as owned bytes; callers receive a scoped borrow that cannot escape.
public struct TLS13ResumptionMasterSecret: ~Copyable, Sendable {
  public let cipherSuite: TLSCipherSuite

  private let secret: SecretBytes

  package init(
    cipherSuite: TLSCipherSuite,
    secret: consuming SecretBytes
  ) {
    self.cipherSuite = cipherSuite
    self.secret = secret
  }

  public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try secret.withBorrowedBytes(body)
  }
}
