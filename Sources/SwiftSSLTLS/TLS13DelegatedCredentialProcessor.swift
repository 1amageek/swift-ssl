import SwiftSSLCore
import SwiftSSLX509

enum TLS13DelegatedCredentialProcessor {
  static let signatureSchemes: ContiguousArray<TLS13SignatureScheme> = [
    .ecdsaP256SHA256, .rsaPSSRSAESHA256, .ed25519,
  ]

  static let delegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme> = [
      .ecdsaP256SHA256, .ed25519,
    ]

  static func activeSubjectPublicKeyInfo(
    for certificateMessage: TLS13CertificateMessage,
    role: TLSRole,
    signatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    delegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >,
    at instant: VerificationInstant
  ) throws(TLS13HandshakeEngineError) -> SubjectPublicKeyInfo {
    guard let leafEntry = certificateMessage.entries.first else {
      throw .certificateVerificationFailed
    }
    switch certificateMessage.certificateType {
    case .rawPublicKey:
      guard leafEntry.delegatedCredential == nil else {
        throw .certificateVerificationFailed
      }
      do {
        return try SubjectPublicKeyInfo(der: leafEntry.certificate.span)
      } catch {
        throw .certificateVerificationFailed
      }
    case .x509:
      let certificate: X509Certificate
      do {
        certificate = try X509Certificate(der: leafEntry.certificate.span)
      } catch let error {
        throw .certificate(error)
      }
      guard let delegatedCredential = leafEntry.delegatedCredential else {
        return certificate.subjectPublicKeyInfo
      }
      do {
        return try RFC9345TLS13DelegatedCredentialValidator().validate(
          delegatedCredential,
          certificate: certificate,
          role: role,
          signatureSchemes: signatureSchemes,
          delegatedCredentialAlgorithms: delegatedCredentialAlgorithms,
          at: instant
        )
      } catch let error {
        throw .delegatedCredential(error)
      }
    }
  }

  static func activeSubjectPublicKeyInfo(
    for entries: borrowing ContiguousArray<TLS13CertificateEntry>,
    role: TLSRole,
    signatureSchemes: borrowing ContiguousArray<TLS13SignatureScheme>,
    delegatedCredentialAlgorithms: borrowing ContiguousArray<
      TLS13SignatureScheme
    >,
    at instant: VerificationInstant
  ) throws(TLS13HandshakeEngineError) -> SubjectPublicKeyInfo {
    guard let leafEntry = entries.first else {
      throw .certificateVerificationFailed
    }
    let certificate: X509Certificate
    do {
      certificate = try X509Certificate(der: leafEntry.certificate.span)
    } catch let error {
      throw .certificate(error)
    }
    guard let delegatedCredential = leafEntry.delegatedCredential else {
      return certificate.subjectPublicKeyInfo
    }
    do {
      return try RFC9345TLS13DelegatedCredentialValidator().validate(
        delegatedCredential,
        certificate: certificate,
        role: role,
        signatureSchemes: signatureSchemes,
        delegatedCredentialAlgorithms: delegatedCredentialAlgorithms,
        at: instant
      )
    } catch let error {
      throw .delegatedCredential(error)
    }
  }
}
