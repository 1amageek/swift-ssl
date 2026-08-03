import SSLCrypto
import SSLX509

public enum TLS13ClientIdentityError: Error, Sendable, Equatable {
  case invalidCertificateCount
  case unsupportedCertificateExtension(index: Int)
  case certificate(index: Int, X509CertificateError)
  case certificateNotValid
  case unsupportedLeafPublicKey
  case crypto(CryptoInputError)
  case certificateKeyMismatch
  case delegatedCredential(TLS13DelegatedCredentialError)
}
