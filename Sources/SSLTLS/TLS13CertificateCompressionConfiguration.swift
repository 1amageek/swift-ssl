public enum TLS13CertificateCompressionConfigurationError:
  Error,
  Sendable,
  Equatable
{
  case noCodecs
  case duplicateAlgorithm(TLS13CertificateCompressionAlgorithm)
  case invalidMaximumUncompressedByteCount(Int)
}

/// Immutable certificate-compression capabilities shared by every transport.
public struct TLS13CertificateCompressionConfiguration: Sendable {
  private let codecs:
    ContiguousArray<any TLS13CertificateCompressionCoding>

  public let maximumUncompressedByteCount: Int

  public init(
    codecs: consuming ContiguousArray<
      any TLS13CertificateCompressionCoding
    >,
    maximumUncompressedByteCount: Int = 0x00FF_FFFF
  ) throws(TLS13CertificateCompressionConfigurationError) {
    guard !codecs.isEmpty else { throw .noCodecs }
    guard maximumUncompressedByteCount > 0,
      maximumUncompressedByteCount <= 0x00FF_FFFF
    else {
      throw .invalidMaximumUncompressedByteCount(
        maximumUncompressedByteCount
      )
    }
    var seen = ContiguousArray<TLS13CertificateCompressionAlgorithm>()
    seen.reserveCapacity(codecs.count)
    var index = 0
    while index < codecs.count {
      let algorithm = codecs[index].algorithm
      guard !seen.contains(algorithm) else {
        throw .duplicateAlgorithm(algorithm)
      }
      seen.append(algorithm)
      index += 1
    }
    self.codecs = consume codecs
    self.maximumUncompressedByteCount = maximumUncompressedByteCount
  }

  public static func zlib(
    maximumUncompressedByteCount: Int = 0x00FF_FFFF
  ) throws(TLS13CertificateCompressionConfigurationError) -> Self {
    try Self(
      codecs: [TLS13ZlibCertificateCompression()],
      maximumUncompressedByteCount: maximumUncompressedByteCount
    )
  }

  package var algorithms:
    ContiguousArray<TLS13CertificateCompressionAlgorithm>
  {
    var result = ContiguousArray<TLS13CertificateCompressionAlgorithm>()
    result.reserveCapacity(codecs.count)
    var index = 0
    while index < codecs.count {
      result.append(codecs[index].algorithm)
      index += 1
    }
    return result
  }

  package func codec(
    for algorithm: TLS13CertificateCompressionAlgorithm
  ) -> (any TLS13CertificateCompressionCoding)? {
    var index = 0
    while index < codecs.count {
      if codecs[index].algorithm == algorithm {
        return codecs[index]
      }
      index += 1
    }
    return nil
  }
}
