import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class TLS13CertificateCompressionTests: XCTestCase {
  func testCertificateCompressionExtensionsAndMessageRoundTrip() throws {
    let clientHello = try TLS13HandshakeCodec.makeClientHello(
      random: ContiguousArray(repeating: 0x11, count: 32).span,
      keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
      certificateCompressionAlgorithms: [.zlib, .brotli]
    )
    let parsedClientHello = try TLS13HandshakeCodec.parseClientHello(
      clientHello.span
    )
    XCTAssertEqual(
      parsedClientHello.certificateCompressionAlgorithms,
      [.zlib, .brotli]
    )

    let certificateRequest = try TLS13HandshakeCodec.makeCertificateRequest(
      certificateCompressionAlgorithms: [.zlib]
    )
    let parsedCertificateRequest = try TLS13HandshakeCodec
      .parseCertificateRequest(certificateRequest.span)
    XCTAssertEqual(
      parsedCertificateRequest.certificateCompressionAlgorithms,
      [.zlib]
    )

    let compressedPayload = ContiguousArray<UInt8>([0x78, 0x01, 0x03, 0x00])
    let message = try TLS13HandshakeCodec.makeCompressedCertificate(
      algorithm: .zlib,
      uncompressedCertificateMessageByteCount: 512,
      compressedCertificateMessage: compressedPayload.span
    )
    let parsedMessage = try TLS13HandshakeCodec.parseCompressedCertificate(
      message.span
    )
    XCTAssertEqual(parsedMessage.algorithm, .zlib)
    XCTAssertEqual(parsedMessage.uncompressedByteCount, 512)
    XCTAssertEqual(
      copy(parsedMessage.compressedCertificateMessage.span),
      compressedPayload
    )
  }

  func testCertificateCompressionWireRejectsInvalidLengthsAndDuplicates() {
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.makeClientHello(
        random: ContiguousArray(repeating: 0x11, count: 32).span,
        keyShare: ContiguousArray(repeating: 0x22, count: 32).span,
        certificateCompressionAlgorithms: [.zlib, .zlib]
      )
    )
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.makeCompressedCertificate(
        algorithm: .zlib,
        uncompressedCertificateMessageByteCount: 0,
        compressedCertificateMessage: ContiguousArray([0x01]).span
      )
    )
    XCTAssertThrowsError(
      try TLS13HandshakeCodec.makeCompressedCertificate(
        algorithm: .zlib,
        uncompressedCertificateMessageByteCount: 1,
        compressedCertificateMessage: Span<UInt8>()
      )
    )
  }

  func testPureSwiftZlibRoundTripsRepetitiveCertificateMessage() throws {
    let payload = repetitivePayload(repetitions: 64)
    let codec = TLS13ZlibCertificateCompression()

    let compressed = try codec.compress(payload.span)
    let decompressed = try codec.decompress(
      compressed.span,
      uncompressedByteCount: payload.count,
      maximumUncompressedByteCount: payload.count
    )

    XCTAssertLessThan(compressed.count, payload.count)
    XCTAssertEqual(copy(decompressed.span), payload)
  }

  func testPureSwiftZlibDecompressesExternalDynamicHuffmanFixture() throws {
    let payload = repetitivePayload(repetitions: 32)
    let compressed = bytes(
      "78daedcdc70dc2300005507aefbd637a0f8450435b801b59200ab6640902728cc"
        + "4f8ccc0fdbf059e71bd1155d1884585e48c5ba6a4c47a3ddf823a0e7fd9e4ce1"
        + "9a382da929b0fc2f8577e04d589cbedf1fafc8160281c89c6e289642a9dc9e6f2"
        + "8562a95ca9d6ea8d2669b53bdd5e7f301c8d27d399325fa84b6db5de6c777bfd"
        + "703c9d2f0656ac58b162c58a152b56ac58b162c5fad7fa036ea5712e"
    )

    let decompressed = try TLS13ZlibCertificateCompression().decompress(
      compressed.span,
      uncompressedByteCount: payload.count,
      maximumUncompressedByteCount: payload.count
    )

    XCTAssertEqual(copy(decompressed.span), payload)
  }

  func testPureSwiftZlibRejectsOutputBeyondConfiguredLimit() throws {
    let payload = repetitivePayload(repetitions: 4)
    let codec = TLS13ZlibCertificateCompression()
    let compressed = try codec.compress(payload.span)

    XCTAssertThrowsError(
      try codec.decompress(
        compressed.span,
        uncompressedByteCount: payload.count,
        maximumUncompressedByteCount: payload.count - 1
      )
    ) { error in
      XCTAssertEqual(
        error as? TLS13CertificateCompressionError,
        .outputLimitExceeded(limit: payload.count - 1)
      )
    }
  }

  func testPureSwiftZlibRejectsCorruptedChecksum() throws {
    let payload = repetitivePayload(repetitions: 4)
    let codec = TLS13ZlibCertificateCompression()
    let compressed = try codec.compress(payload.span)
    var corrupted = copy(compressed.span)
    corrupted[corrupted.count - 1] ^= 0x01

    XCTAssertThrowsError(
      try codec.decompress(
        corrupted.span,
        uncompressedByteCount: payload.count,
        maximumUncompressedByteCount: payload.count
      )
    ) { error in
      XCTAssertEqual(
        error as? TLS13CertificateCompressionError,
        .checksumMismatch
      )
    }
  }

  private func repetitivePayload(
    repetitions: Int
  ) -> ContiguousArray<UInt8> {
    var unit = ContiguousArray(
      "TLS 1.3 certificate compression differential fixture: ".utf8
    )
    unit.append(contentsOf: 0..<64)
    var payload = ContiguousArray<UInt8>()
    payload.reserveCapacity(unit.count * repetitions)
    for _ in 0..<repetitions {
      payload.append(contentsOf: unit)
    }
    return payload
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(value.utf8.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        preconditionFailure("Fixture contains non-hexadecimal data")
      }
      result.append(byte)
      index = next
    }
    return result
  }

  private func copy(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bytes.count)
    var index = 0
    while index < bytes.count {
      result.append(bytes[index])
      index += 1
    }
    return result
  }
}
