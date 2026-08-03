import SwiftSSLCore
import SwiftSSLX509

/// Validates a client Certificate message without performing I/O.
public protocol TLS13ClientCertificateValidating: Sendable {
  func validate(
    _ message: borrowing TLS13CertificateMessage,
    at instant: VerificationInstant
  ) throws(TLS13ClientCertificateValidationError)
    -> TLS13ValidatedClientCertificate
}
