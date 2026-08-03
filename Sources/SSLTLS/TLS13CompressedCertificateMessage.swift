import SSLCore

/// An owned RFC 8879 CompressedCertificate handshake message payload.
public struct TLS13CompressedCertificateMessage: Sendable, Hashable {
  public let algorithm: TLS13CertificateCompressionAlgorithm
  public let uncompressedByteCount: Int
  public let compressedCertificateMessage: OwnedBytes

  internal init(
    algorithm: TLS13CertificateCompressionAlgorithm,
    uncompressedByteCount: Int,
    compressedCertificateMessage: consuming OwnedBytes
  ) {
    self.algorithm = algorithm
    self.uncompressedByteCount = uncompressedByteCount
    self.compressedCertificateMessage = compressedCertificateMessage
  }
}
