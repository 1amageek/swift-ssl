import SwiftSSLX509

public enum TLS13ServerCertificateValidationError:
  Error,
  Sendable,
  Equatable
{
  case invalidCertificateMessage
  case certificate(index: Int, X509CertificateError)
  case path(X509PathError)
  case ocsp(index: Int, OCSPResponseError)
  case revocation(X509RevocationError)
  case missingCertificateTransparencyEvidence
  case certificateTransparency(CertificateTransparencyError)
  case unsupportedLeafPublicKey
}
