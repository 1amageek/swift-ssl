import SSLCore
import SSLX509

public struct RFC9345TLS13DelegatedCredentialValidator:
  TLS13DelegatedCredentialValidating,
  Sendable
{
  public static let maximumLifetimeSeconds: UInt32 = 7 * 24 * 60 * 60

  private let maximumLifetime: UInt32
  private let codec: RFC9345TLS13DelegatedCredentialCodec

  public init(
    maximumLifetime: UInt32 = maximumLifetimeSeconds
  ) {
    self.maximumLifetime = maximumLifetime
    codec = RFC9345TLS13DelegatedCredentialCodec()
  }

  public func validate(
    _ delegatedCredential: TLS13DelegatedCredential,
    certificate: X509Certificate,
    role: TLSRole,
    signatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    delegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >,
    at instant: VerificationInstant
  ) throws(TLS13DelegatedCredentialError) -> SubjectPublicKeyInfo {
    guard certificate.validity.contains(instant) else {
      throw .certificateNotValid
    }
    guard signatureSchemes.contains(
      delegatedCredential.delegationAlgorithm
    ) else {
      throw .delegationAlgorithmNotAdvertised
    }
    guard delegatedCredentialAlgorithms.contains(
      delegatedCredential.certificateVerifyAlgorithm
    ) else {
      throw .certificateVerifyAlgorithmNotAdvertised
    }
    do {
      try certificate.validateDelegatedCredentialUsage()
    } catch let error {
      throw .delegationUsage(error)
    }

    let notBefore = certificate.validity.notBeforeVerificationInstant
    let (expirationSeconds, expirationOverflow) =
      notBefore.secondsSinceUnixEpoch.addingReportingOverflow(
        Int64(delegatedCredential.validTime)
      )
    guard !expirationOverflow else {
      throw .credentialLifetimeExceeded
    }
    let expiration: VerificationInstant
    do {
      expiration = try VerificationInstant(
        secondsSinceUnixEpoch: expirationSeconds,
        nanoseconds: notBefore.nanoseconds
      )
    } catch {
      throw .credentialLifetimeExceeded
    }
    guard instant <= expiration else {
      throw .credentialExpired
    }
    let (maximumExpirationSeconds, maximumOverflow) =
      instant.secondsSinceUnixEpoch.addingReportingOverflow(
        Int64(maximumLifetime)
      )
    guard !maximumOverflow else {
      throw .credentialLifetimeExceeded
    }
    let maximumExpiration: VerificationInstant
    do {
      maximumExpiration = try VerificationInstant(
        secondsSinceUnixEpoch: maximumExpirationSeconds,
        nanoseconds: instant.nanoseconds
      )
    } catch {
      throw .credentialLifetimeExceeded
    }
    guard expiration <= maximumExpiration else {
      throw .credentialLifetimeExceeded
    }
    guard expiration
      < certificate.validity.notAfterVerificationInstant
    else {
      throw .credentialOutlivesCertificate
    }

    let signingInput: OwnedBytes
    do {
      signingInput = try certificate.withDERBytes {
        certificateDER throws(TLS13DelegatedCredentialError) in
        try delegatedCredential.subjectPublicKeyInfo.withDERBytes {
          publicKeyDER throws(TLS13DelegatedCredentialError) in
          try codec.makeSigningInput(
            validTime: delegatedCredential.validTime,
            certificateVerifyAlgorithm:
              delegatedCredential.certificateVerifyAlgorithm,
            subjectPublicKeyInfoDER: publicKeyDER,
            delegationAlgorithm: delegatedCredential.delegationAlgorithm,
            role: role,
            certificateDER: certificateDER
          )
        }
      }
    } catch let error {
      throw error
    }
    let certificateKey: TLS13CertificateVerificationKey
    do {
      certificateKey = try TLS13CertificateVerificationKey(
        subjectPublicKeyInfo: certificate.subjectPublicKeyInfo
      )
    } catch let error {
      throw .crypto(error)
    }
    let delegationSignature = TLS13CertificateVerify(
      signatureScheme: delegatedCredential.delegationAlgorithm,
      signature: delegatedCredential.signature
    )
    let signatureIsValid: Bool
    do {
      signatureIsValid = try certificateKey.verify(
        delegationSignature,
        signedMessage: signingInput.span
      )
    } catch {
      throw .invalidDelegationSignature
    }
    guard signatureIsValid else {
      throw .invalidDelegationSignature
    }
    return delegatedCredential.subjectPublicKeyInfo
  }
}
import TLSTypes
