import SwiftSSLCore
import SwiftSSLX509

/// Public credential material selected by an external credential provider.
/// Private-key material remains outside the TLS engine.
public struct TLS13CredentialDescriptor: Sendable, Hashable {
  public let identifier: OwnedBytes
  public let certificateEntries: ContiguousArray<TLS13CertificateEntry>
  public let rawPublicKey: OwnedBytes?
  public let certificateType: TLS13CertificateType
  public let signatureScheme: TLS13SignatureScheme

  public init(
    identifier: Span<UInt8>,
    certificateEntries: consuming ContiguousArray<TLS13CertificateEntry>,
    signatureScheme: TLS13SignatureScheme,
    verificationInstant: VerificationInstant
  ) throws(TLS13CredentialError) {
    guard !identifier.isEmpty, identifier.count <= UInt16.max else {
      throw .invalidIdentifier
    }
    guard !certificateEntries.isEmpty,
      certificateEntries.count <= TLS13CertificateMessage.maximumCertificateCount
    else {
      throw .invalidCertificateCount
    }
    var leaf: X509Certificate?
    var index = 0
    while index < certificateEntries.count {
      guard index == 0
        || certificateEntries[index].delegatedCredential == nil
      else {
        throw .invalidCertificateCount
      }
      let certificateBytes = certificateEntries[index].certificate
      do {
        let certificate = try X509Certificate(der: certificateBytes.span)
        if index == 0 { leaf = certificate }
      } catch let error {
        throw .certificate(index: index, error: error)
      }
      index += 1
    }
    guard let leaf else { throw .invalidCertificateCount }
    guard leaf.validity.contains(verificationInstant) else {
      throw .certificateNotValid
    }
    let activeSubjectPublicKeyInfo =
      certificateEntries[0].delegatedCredential?.subjectPublicKeyInfo
      ?? leaf.subjectPublicKeyInfo
    guard signatureScheme.matches(activeSubjectPublicKeyInfo) else {
      throw .signatureSchemeMismatch
    }
    self.identifier = OwnedBytes(copying: identifier)
    self.certificateEntries = certificateEntries
    rawPublicKey = nil
    certificateType = .x509
    self.signatureScheme = signatureScheme
  }

  public init(
    identifier: Span<UInt8>,
    rawPublicKeyDER: Span<UInt8>,
    signatureScheme: TLS13SignatureScheme
  ) throws(TLS13CredentialError) {
    guard !identifier.isEmpty, identifier.count <= UInt16.max else {
      throw .invalidIdentifier
    }
    let subjectPublicKeyInfo: SubjectPublicKeyInfo
    do {
      subjectPublicKeyInfo = try SubjectPublicKeyInfo(der: rawPublicKeyDER)
    } catch let error {
      throw .rawPublicKey(error)
    }
    guard signatureScheme.matches(subjectPublicKeyInfo) else {
      throw .signatureSchemeMismatch
    }
    self.identifier = OwnedBytes(copying: identifier)
    certificateEntries = []
    rawPublicKey = OwnedBytes(copying: rawPublicKeyDER)
    certificateType = .rawPublicKey
    self.signatureScheme = signatureScheme
  }
}
