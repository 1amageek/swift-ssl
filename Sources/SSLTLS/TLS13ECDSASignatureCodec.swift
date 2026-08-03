import SSLCore
import SSLCrypto

/// Strict conversion between TLS DER ECDSA signatures and fixed-width P-256 values.
enum TLS13ECDSASignatureCodec {
  static func encodeP256(
    _ rawSignature: Span<UInt8>
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    guard rawSignature.count == P256ECDSA.signatureByteCount else {
      throw .invalidLength(
        expected: P256ECDSA.signatureByteCount,
        actual: rawSignature.count
      )
    }

    let r = rawSignature.extracting(0..<32)
    let s = rawSignature.extracting(32..<64)
    let rLength = encodedIntegerLength(r)
    let sLength = encodedIntegerLength(s)
    let bodyLength = 2 + rLength + 2 + sLength
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(bodyLength + 2)
    result.append(0x30)
    result.append(UInt8(bodyLength))
    appendInteger(r, encodedLength: rLength, to: &result)
    appendInteger(s, encodedLength: sLength, to: &result)
    return result
  }

  static func decodeP256(
    _ signature: Span<UInt8>
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    guard signature.count >= 8,
      signature[0] == 0x30,
      signature[1] < 0x80,
      Int(signature[1]) == signature.count - 2
    else {
      throw .nonCanonicalEncoding
    }

    var offset = 2
    var result = ContiguousArray<UInt8>(repeating: 0, count: 64)
    try copyInteger(
      from: signature,
      offset: &offset,
      into: &result,
      destinationOffset: 0
    )
    try copyInteger(
      from: signature,
      offset: &offset,
      into: &result,
      destinationOffset: 32
    )
    guard offset == signature.count else {
      throw .nonCanonicalEncoding
    }
    return result
  }

  private static func encodedIntegerLength(_ bytes: Span<UInt8>) -> Int {
    var first = 0
    while first + 1 < bytes.count, bytes[first] == 0 {
      first += 1
    }
    return bytes.count - first + (bytes[first] & 0x80 == 0 ? 0 : 1)
  }

  private static func appendInteger(
    _ bytes: Span<UInt8>,
    encodedLength: Int,
    to result: inout ContiguousArray<UInt8>
  ) {
    result.append(0x02)
    result.append(UInt8(encodedLength))
    var first = 0
    while first + 1 < bytes.count, bytes[first] == 0 {
      first += 1
    }
    if bytes[first] & 0x80 != 0 {
      result.append(0)
    }
    var index = first
    while index < bytes.count {
      result.append(bytes[index])
      index += 1
    }
  }

  private static func copyInteger(
    from signature: Span<UInt8>,
    offset: inout Int,
    into result: inout ContiguousArray<UInt8>,
    destinationOffset: Int
  ) throws(CryptoInputError) {
    guard offset <= signature.count - 2,
      signature[offset] == 0x02
    else {
      throw .nonCanonicalEncoding
    }
    let byteCount = Int(signature[offset + 1])
    offset += 2
    guard byteCount > 0,
      byteCount <= 33,
      offset <= signature.count - byteCount
    else {
      throw .nonCanonicalEncoding
    }

    let bytes = signature.extracting(offset..<(offset + byteCount))
    guard bytes[0] & 0x80 == 0 else {
      throw .nonCanonicalEncoding
    }
    var sourceOffset = 0
    if bytes[0] == 0 {
      guard byteCount > 1, bytes[1] & 0x80 != 0 else {
        throw .nonCanonicalEncoding
      }
      sourceOffset = 1
    }
    let magnitudeByteCount = byteCount - sourceOffset
    guard magnitudeByteCount <= 32 else {
      throw .nonCanonicalEncoding
    }
    var index = 0
    while index < magnitudeByteCount {
      result[
        destinationOffset + 32 - magnitudeByteCount + index
      ] = bytes[sourceOffset + index]
      index += 1
    }
    offset += byteCount
  }
}
