import SSLCore

/// An owned RFC 8446 Certificate message body.
public struct TLS13CertificateMessage: Sendable, Hashable {
  public static let maximumCertificateCount = 8

  public let requestContext: OwnedBytes
  public let entries: ContiguousArray<TLS13CertificateEntry>
  public let certificateType: TLS13CertificateType

  internal init(
    requestContext: consuming OwnedBytes,
    entries: consuming ContiguousArray<TLS13CertificateEntry>,
    certificateType: TLS13CertificateType
  ) {
    self.requestContext = requestContext
    self.entries = entries
    self.certificateType = certificateType
  }
}
