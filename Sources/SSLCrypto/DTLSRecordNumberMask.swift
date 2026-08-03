import SSLCore

/// Package boundary for RFC 9147 record-number protection primitives.
package enum DTLSRecordNumberMask {
  package static func aes(
    key: Span<UInt8>,
    sample: Span<UInt8>
  ) throws(AEADError) -> ContiguousArray<UInt8> {
    guard key.count == 16 || key.count == 32 else {
      throw .invalidKeyLength(expected: [16, 32], actual: key.count)
    }
    guard sample.count == 16 else {
      throw .invalidNonceLength(expected: 16, actual: sample.count)
    }
    let cipher = AESBlockCipher(key: key)
    var output = ContiguousArray<UInt8>(repeating: 0, count: 16)
    output.withUnsafeMutableBufferPointer { buffer in
      var destination = MutableSpan(_unsafeStart: buffer.baseAddress!, count: 16)
      cipher.encrypt(sample, into: &destination)
    }
    return output
  }
}
