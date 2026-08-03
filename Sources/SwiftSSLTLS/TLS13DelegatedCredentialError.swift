import SwiftSSLCrypto
import SwiftSSLX509

public enum TLS13DelegatedCredentialError: Error, Sendable, Equatable {
  case malformedCredential
  case subjectPublicKeyInfo(SubjectPublicKeyInfoError)
  case unsupportedCertificateVerifyAlgorithm
  case unsupportedDelegationAlgorithm
  case certificateVerifyAlgorithmNotAdvertised
  case delegationAlgorithmNotAdvertised
  case delegationUsage(X509DelegationUsageError)
  case certificateNotValid
  case credentialExpired
  case credentialLifetimeExceeded
  case credentialOutlivesCertificate
  case certificateKeyMismatch
  case invalidDelegationSignature
  case crypto(CryptoInputError)
  case signing(TLS13SigningError)
}
