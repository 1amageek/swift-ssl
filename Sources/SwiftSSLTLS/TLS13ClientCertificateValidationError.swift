import SwiftSSLX509

public enum TLS13ClientCertificateValidationError:
  Error,
  Sendable,
  Equatable
{
  case invalidCertificateMessage
  case certificate(index: Int, X509CertificateError)
  case path(X509PathError)
  case ocsp(index: Int, OCSPResponseError)
  case revocation(X509RevocationError)
  case unsupportedLeafPublicKey
}
