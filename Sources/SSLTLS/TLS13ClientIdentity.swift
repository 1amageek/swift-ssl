import SSLCore
import SSLCrypto
import SSLX509

/// Client-owned certificate chain and noncopyable signing capability.
public struct TLS13ClientIdentity: ~Copyable, Sendable {
  package let certificateEntries: ContiguousArray<TLS13CertificateEntry>
  private let signingKey: TLS13SigningKey

  public init(
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signingKey: consuming TLS13SigningKey,
    verificationInstant: VerificationInstant
  ) throws(TLS13ClientIdentityError) {
    guard !certificateEntries.isEmpty,
      certificateEntries.count <= TLS13CertificateMessage.maximumCertificateCount
    else {
      throw .invalidCertificateCount
    }
    var leaf: X509Certificate?
    var index = 0
    while index < certificateEntries.count {
      let entry = certificateEntries[index]
      guard entry.stapledOCSPResponse == nil,
        entry.signedCertificateTimestampList == nil,
        index == 0 || entry.delegatedCredential == nil
      else {
        throw .unsupportedCertificateExtension(index: index)
      }
      do {
        let certificate = try X509Certificate(der: entry.certificate.span)
        if index == 0 { leaf = certificate }
      } catch let error {
        throw .certificate(index: index, error)
      }
      index += 1
    }
    guard let leaf else { throw .invalidCertificateCount }
    guard leaf.validity.contains(verificationInstant) else {
      throw .certificateNotValid
    }
    let activeSubjectPublicKeyInfo: SubjectPublicKeyInfo
    if let delegatedCredential = certificateEntries[0].delegatedCredential {
      do {
        activeSubjectPublicKeyInfo = try
          RFC9345TLS13DelegatedCredentialValidator().validate(
            delegatedCredential,
            certificate: leaf,
            role: .client,
            signatureSchemes:
              TLS13DelegatedCredentialProcessor.signatureSchemes,
            delegatedCredentialAlgorithms:
              TLS13DelegatedCredentialProcessor.delegatedCredentialAlgorithms,
            at: verificationInstant
          )
      } catch let error {
        throw .delegatedCredential(error)
      }
    } else {
      activeSubjectPublicKeyInfo = leaf.subjectPublicKeyInfo
    }
    guard signingKey.signatureScheme.matches(activeSubjectPublicKeyInfo) else {
      throw .unsupportedLeafPublicKey
    }
    let publicKeyBytes: ContiguousArray<UInt8>
    do {
      publicKeyBytes = try signingKey.publicKeyBytes()
    } catch let error {
      throw .crypto(error)
    }
    let publicKey = OwnedBytes(consuming: publicKeyBytes)
    let keyMatches = activeSubjectPublicKeyInfo.withPublicKeyBytes { bytes in
      ConstantTime.equal(bytes, publicKey.span)
    }
    guard keyMatches else { throw .certificateKeyMismatch }
    self.certificateEntries = certificateEntries
    self.signingKey = signingKey
  }

  package var signatureScheme: TLS13SignatureScheme {
    signingKey.signatureScheme
  }

  package var delegatedCredential: TLS13DelegatedCredential? {
    certificateEntries.first?.delegatedCredential
  }

  package borrowing func sign(
    message: Span<UInt8>
  ) throws(TLS13SigningError) -> ContiguousArray<UInt8> {
    try signingKey.sign(message: message)
  }
}
