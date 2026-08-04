import SSLCore
import SSLX509

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

  /// Creates an independent owned copy of a certificate message.
  ///
  /// This is intentionally an explicit boundary operation. The handshake
  /// engine borrows certificate messages while validating them; callers that
  /// need to retain a message past that borrow must request this copy.
  public init(copying message: borrowing TLS13CertificateMessage) {
    var copiedEntries = ContiguousArray<TLS13CertificateEntry>()
    copiedEntries.reserveCapacity(message.entries.count)
    for entry in message.entries {
      copiedEntries.append(
        TLS13CertificateEntry(
          certificate: CertificateBytes(copying: entry.certificate.span),
          stapledOCSPResponse: entry.stapledOCSPResponse.map {
            OwnedBytes(copying: $0.span)
          },
          signedCertificateTimestampList: entry.signedCertificateTimestampList.map {
            OwnedBytes(copying: $0.span)
          },
          delegatedCredential: entry.delegatedCredential
        )
      )
    }
    self.init(
      requestContext: OwnedBytes(copying: message.requestContext.span),
      entries: copiedEntries,
      certificateType: message.certificateType
    )
  }
}
