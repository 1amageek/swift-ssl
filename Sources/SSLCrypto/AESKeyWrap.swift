import SSLCore

/// Errors produced by the RFC 3394 AES key-wrap construction.
public enum AESKeyWrapError: Error, Sendable, Equatable {
  case invalidKeyLength(actual: Int)
  case invalidInputLength(actual: Int)
  case invalidOutputLength(expected: Int, actual: Int)
  case integrityFailure
}

/// RFC 3394 AES key wrapping with caller-owned input and output storage.
///
/// The static operations keep the AES key schedule scoped to the call. The
/// caller owns all input and output buffers; no pointer or borrowed span
/// escapes this boundary. Intermediate blocks contain key material and are
/// wiped before the operation returns.
public enum AESKeyWrap {
  public static let overhead = 8

  private static let initializationVector: [UInt8] = [
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
  ]

  /// Wraps a key into `output` using RFC 3394.
  public static func wrap(
    key: Span<UInt8>,
    plaintext: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AESKeyWrapError) {
    try validateKey(key)
    guard plaintext.count >= 16, plaintext.count % 8 == 0 else {
      throw .invalidInputLength(actual: plaintext.count)
    }
    let expectedOutputCount = plaintext.count + Self.overhead
    guard output.count == expectedOutputCount else {
      throw .invalidOutputLength(expected: expectedOutputCount, actual: output.count)
    }

    let cipher = AESBlockCipher(key: key)
    var a = Self.initializationVector
    var index = 0
    while index < 8 {
      output[index] = a[index]
      index += 1
    }
    while index < expectedOutputCount {
      output[index] = plaintext[index - 8]
      index += 1
    }

    let blockCount = plaintext.count / 8
    var round = 0
    while round < 6 {
      var block = 0
      while block < blockCount {
        let blockOffset = 8 + block * 8
        var input = ContiguousArray<UInt8>(repeating: 0, count: 16)
        var inputIndex = 0
        while inputIndex < 8 {
          input[inputIndex] = a[inputIndex]
          input[inputIndex + 8] = output[blockOffset + inputIndex]
          inputIndex += 1
        }

        let encrypted = encrypt(cipher, block: input)
        let t = UInt64(blockCount * round + block + 1)
        var byte = 0
        while byte < 8 {
          a[byte] = encrypted[byte] ^ UInt8(truncatingIfNeeded: t >> UInt64(56 - byte * 8))
          output[blockOffset + byte] = encrypted[byte + 8]
          byte += 1
        }
        block += 1
      }
      round += 1
    }

    index = 0
    while index < 8 {
      output[index] = a[index]
      index += 1
    }
  }

  /// Unwraps an RFC 3394 ciphertext into `output`.
  public static func unwrap(
    key: Span<UInt8>,
    wrapped: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AESKeyWrapError) {
    try validateKey(key)
    guard wrapped.count >= 24, wrapped.count % 8 == 0 else {
      throw .invalidInputLength(actual: wrapped.count)
    }
    let expectedOutputCount = wrapped.count - Self.overhead
    guard output.count == expectedOutputCount else {
      throw .invalidOutputLength(expected: expectedOutputCount, actual: output.count)
    }

    let cipher = AESBlockCipher(key: key)
    var a = ContiguousArray<UInt8>(repeating: 0, count: 8)
    var initialIndex = 0
    while initialIndex < 8 {
      a[initialIndex] = wrapped[initialIndex]
      initialIndex += 1
    }
    let blockCount = expectedOutputCount / 8
    var blocks = ContiguousArray<UInt8>(repeating: 0, count: expectedOutputCount)
    var wrappedIndex = 8
    while wrappedIndex < wrapped.count {
      blocks[wrappedIndex - 8] = wrapped[wrappedIndex]
      wrappedIndex += 1
    }
    var round = 5
    while round >= 0 {
      var block = blockCount
      while block >= 1 {
        let blockOffset = (block - 1) * 8
        let t = UInt64(blockCount * round + block)
        var input = ContiguousArray<UInt8>(repeating: 0, count: 16)
        var inputIndex = 0
        while inputIndex < 8 {
          input[inputIndex] = a[inputIndex] ^ UInt8(truncatingIfNeeded: t >> UInt64(56 - inputIndex * 8))
          input[inputIndex + 8] = blocks[blockOffset + inputIndex]
          inputIndex += 1
        }

        let decrypted = decrypt(cipher, block: input)
        var byte = 0
        while byte < 8 {
          a[byte] = decrypted[byte]
          blocks[blockOffset + byte] = decrypted[byte + 8]
          byte += 1
        }
        block -= 1
      }
      round -= 1
    }

    var mismatch: UInt8 = 0
    var byte = 0
    while byte < Self.initializationVector.count {
      mismatch |= a[byte] ^ Self.initializationVector[byte]
      byte += 1
    }
    guard mismatch == 0 else {
      throw .integrityFailure
    }

    var outputIndex = 0
    while outputIndex < blocks.count {
      output[outputIndex] = blocks[outputIndex]
      outputIndex += 1
    }
  }

  private static func validateKey(_ key: Span<UInt8>) throws(AESKeyWrapError) {
    guard key.count == 16 || key.count == 24 || key.count == 32 else {
      throw .invalidKeyLength(actual: key.count)
    }
  }

  private static func encrypt(
    _ cipher: borrowing AESBlockCipher,
    block: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: 16)
    var outputSpan = output.mutableSpan
    cipher.encrypt(block.span, into: &outputSpan)
    return output
  }

  private static func decrypt(
    _ cipher: borrowing AESBlockCipher,
    block: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: 16)
    var outputSpan = output.mutableSpan
    cipher.decrypt(block.span, into: &outputSpan)
    return output
  }
}
