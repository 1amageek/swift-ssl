import SSLCore

/// Bridges RFC 8879 wire messages and pluggable compression codecs.
package enum TLS13CertificateCompressionProcessor {
  package static func decode(
    _ encodedMessage: Span<UInt8>,
    certificateType: TLS13CertificateType,
    configuration: TLS13CertificateCompressionConfiguration?
  ) throws(TLS13HandshakeEngineError) -> TLS13CertificateMessage {
    guard !encodedMessage.isEmpty else { throw .malformedInput }
    if encodedMessage[0] == TLS13HandshakeCodec.certificateType {
      if let configuration {
        guard encodedMessage.count
          <= configuration.maximumUncompressedByteCount
        else {
          throw .certificateCompression(
            .outputLimitExceeded(
              limit: configuration.maximumUncompressedByteCount
            )
          )
        }
      }
      return try engineTry {
        try TLS13HandshakeCodec.parseCertificateMessage(
          encodedMessage,
          certificateType: certificateType
        )
      }
    }
    guard encodedMessage[0]
      == TLS13HandshakeCodec.compressedCertificateType,
      let configuration
    else {
      throw .malformedInput
    }
    let compressed = try engineTry {
      try TLS13HandshakeCodec.parseCompressedCertificate(encodedMessage)
    }
    guard let codec = configuration.codec(for: compressed.algorithm) else {
      throw .malformedInput
    }
    let uncompressed: OwnedBytes
    do {
      uncompressed = try codec.decompress(
        compressed.compressedCertificateMessage.span,
        uncompressedByteCount: compressed.uncompressedByteCount,
        maximumUncompressedByteCount:
          configuration.maximumUncompressedByteCount
      )
    } catch let error {
      throw .certificateCompression(error)
    }
    guard !uncompressed.isEmpty,
      uncompressed[0] == TLS13HandshakeCodec.certificateType
    else {
      throw .certificateCompression(.malformedDeflateStream)
    }
    do {
      return try TLS13HandshakeCodec.parseCertificateMessage(
        uncompressed.span,
        certificateType: certificateType
      )
    } catch let error {
      throw mapHandshakeEngineError(error)
    }
  }

  package static func encodeIfUseful(
    _ uncompressed: OwnedBytes,
    peerAlgorithms: borrowing ContiguousArray<
      TLS13CertificateCompressionAlgorithm
    >,
    configuration: TLS13CertificateCompressionConfiguration?
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    guard let configuration,
      uncompressed.count <= configuration.maximumUncompressedByteCount
    else {
      return uncompressed
    }
    var algorithmIndex = 0
    var selectedCodec: (any TLS13CertificateCompressionCoding)?
    while algorithmIndex < peerAlgorithms.count {
      if let codec = configuration.codec(
        for: peerAlgorithms[algorithmIndex]
      ) {
        selectedCodec = codec
        break
      }
      algorithmIndex += 1
    }
    guard let selectedCodec else { return uncompressed }
    let compressed: OwnedBytes
    do {
      compressed = try selectedCodec.compress(uncompressed.span)
    } catch let error {
      throw .certificateCompression(error)
    }
    let wire: OwnedBytes
    do {
      wire = try TLS13HandshakeCodec.makeCompressedCertificate(
        algorithm: selectedCodec.algorithm,
        uncompressedCertificateMessageByteCount: uncompressed.count,
        compressedCertificateMessage: compressed.span
      )
    } catch let error {
      throw mapHandshakeEngineError(error)
    }
    return wire.count < uncompressed.count ? wire : uncompressed
  }
}
