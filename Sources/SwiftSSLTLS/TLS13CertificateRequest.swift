import SwiftSSLCore

/// One TLS 1.3 CertificateRequest with owned selection parameters.
public struct TLS13CertificateRequest: Sendable, Hashable {
  public let requestContext: OwnedBytes
  public let signatureSchemes: ContiguousArray<TLS13SignatureScheme>
  public let certificateCompressionAlgorithms:
    ContiguousArray<TLS13CertificateCompressionAlgorithm>
  public let delegatedCredentialAlgorithms:
    ContiguousArray<TLS13SignatureScheme>

  internal init(
    requestContext: consuming OwnedBytes,
    signatureSchemes: consuming ContiguousArray<TLS13SignatureScheme>,
    certificateCompressionAlgorithms: consuming ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    >,
    delegatedCredentialAlgorithms: consuming ContiguousArray<
      TLS13SignatureScheme
    >
  ) {
    self.requestContext = requestContext
    self.signatureSchemes = signatureSchemes
    self.certificateCompressionAlgorithms = certificateCompressionAlgorithms
    self.delegatedCredentialAlgorithms = delegatedCredentialAlgorithms
  }
}
