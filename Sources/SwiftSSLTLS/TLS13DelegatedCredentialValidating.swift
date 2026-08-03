import SwiftSSLCore
import SwiftSSLX509

public protocol TLS13DelegatedCredentialValidating: Sendable {
  func validate(
    _ delegatedCredential: TLS13DelegatedCredential,
    certificate: X509Certificate,
    role: TLSRole,
    signatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    delegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >,
    at instant: VerificationInstant
  ) throws(TLS13DelegatedCredentialError) -> SubjectPublicKeyInfo
}
