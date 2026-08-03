import SwiftSSLCore
import SwiftSSLX509

/// Validates a server Certificate message without performing I/O.
public protocol TLS13ServerCertificateValidating: Sendable {
  func validate(
    _ message: borrowing TLS13CertificateMessage,
    serverName: Span<UInt8>?,
    at instant: VerificationInstant
  ) throws(TLS13ServerCertificateValidationError) -> SubjectPublicKeyInfo
}
