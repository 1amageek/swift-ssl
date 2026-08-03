import SwiftSSLX509

/// Path-validated client certificate material awaiting proof-of-possession.
///
/// The server handshake exposes this value only after CertificateVerify and
/// Finished have authenticated the peer's private-key possession.
public struct TLS13ValidatedClientCertificate: Sendable {
  public let certificateMessage: TLS13CertificateMessage
  public let leafSubjectPublicKeyInfo: SubjectPublicKeyInfo

  public init(
    certificateMessage: TLS13CertificateMessage,
    leafSubjectPublicKeyInfo: SubjectPublicKeyInfo
  ) {
    self.certificateMessage = certificateMessage
    self.leafSubjectPublicKeyInfo = leafSubjectPublicKeyInfo
  }
}
