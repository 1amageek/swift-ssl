import SwiftSSLCore
import SwiftSSLX509

/// One RFC 8446 CertificateEntry with the modern stapled-evidence extensions.
public struct TLS13CertificateEntry: Sendable, Hashable {
  public let certificate: CertificateBytes
  public let stapledOCSPResponse: OwnedBytes?
  public let signedCertificateTimestampList: OwnedBytes?
  public let delegatedCredential: TLS13DelegatedCredential?

  public init(
    certificateDER: Span<UInt8>,
    stapledOCSPResponse: Span<UInt8>? = nil,
    signedCertificateTimestampList: Span<UInt8>? = nil,
    delegatedCredential: TLS13DelegatedCredential? = nil
  ) throws(TLS13HandshakeError) {
    guard !certificateDER.isEmpty,
      certificateDER.count <= 0x00FF_FFFF,
      stapledOCSPResponse?.isEmpty != true,
      stapledOCSPResponse?.count ?? 0 <= Int(UInt16.max) - 4,
      signedCertificateTimestampList?.isEmpty != true,
      signedCertificateTimestampList?.count ?? 0 <= Int(UInt16.max)
    else {
      throw .malformedMessage
    }
    certificate = CertificateBytes(copying: certificateDER)
    if let stapledOCSPResponse {
      self.stapledOCSPResponse = OwnedBytes(copying: stapledOCSPResponse)
    } else {
      self.stapledOCSPResponse = nil
    }
    if let signedCertificateTimestampList {
      self.signedCertificateTimestampList = OwnedBytes(
        copying: signedCertificateTimestampList
      )
    } else {
      self.signedCertificateTimestampList = nil
    }
    self.delegatedCredential = delegatedCredential
  }

  internal init(
    certificate: consuming CertificateBytes,
    stapledOCSPResponse: consuming OwnedBytes?,
    signedCertificateTimestampList: consuming OwnedBytes?,
    delegatedCredential: TLS13DelegatedCredential?
  ) {
    self.certificate = certificate
    self.stapledOCSPResponse = stapledOCSPResponse
    self.signedCertificateTimestampList = signedCertificateTimestampList
    self.delegatedCredential = delegatedCredential
  }
}
