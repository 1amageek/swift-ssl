import SSLX509

public enum TLS13CredentialError: Error, Sendable, Equatable {
  case invalidIdentifier
  case invalidCertificateCount
  case certificate(index: Int, error: X509CertificateError)
  case rawPublicKey(SubjectPublicKeyInfoError)
  case certificateNotValid
  case signatureSchemeMismatch
}
