import SSLCore

/// AES-128 counter mode for protocols that need a reusable keystream context.
///
/// The key schedule is owned by this value. The payload remains owned by the
/// caller and is XORed in place; the counter and block scratch storage never
/// escape the synchronous operation.
public struct AES128CounterMode: ~Copyable, Sendable {
  private var blockCipher: AESBlockCipher

  public init(key: Span<UInt8>) throws(CryptoInputError) {
    guard key.count == 16 else {
      throw .invalidLength(expected: 16, actual: key.count)
    }
    self.blockCipher = AESBlockCipher(key: key)
  }

  public func applyKeystream(
    to bytes: inout [UInt8],
    range: Range<Int>,
    initialCounter: Span<UInt8>
  ) throws(CryptoInputError) {
    guard initialCounter.count == 16 else {
      throw .invalidLength(expected: 16, actual: initialCounter.count)
    }
    guard range.lowerBound >= 0,
          range.upperBound >= range.lowerBound,
          range.upperBound <= bytes.count else {
      throw .invalidRange
    }
    guard !range.isEmpty else { return }

    var counter = [UInt8](repeating: 0, count: 16)
    var keystream = [UInt8](repeating: 0, count: 16)
    initialCounter.withUnsafeBufferPointer { source in
      counter.withUnsafeMutableBufferPointer { destination in
        destination.baseAddress!.initialize(
          from: source.baseAddress!,
          count: 16
        )
      }
    }

    var offset = range.lowerBound
    while offset < range.upperBound {
      counter.withUnsafeBufferPointer { input in
        keystream.withUnsafeMutableBufferPointer { output in
          let inputSpan = Span(_unsafeStart: input.baseAddress!, count: 16)
          var outputSpan = MutableSpan(_unsafeStart: output.baseAddress!, count: 16)
          blockCipher.encrypt(inputSpan, into: &outputSpan)
        }
      }

      let count = min(16, range.upperBound - offset)
      bytes.withUnsafeMutableBufferPointer { destination in
        var index = 0
        while index < count {
          destination[offset + index] ^= keystream[index]
          index += 1
        }
      }
      offset += count
      Self.increment(&counter)
    }
  }

  private static func increment(_ counter: inout [UInt8]) {
    var index = counter.count
    while index > 0 {
      index -= 1
      counter[index] &+= 1
      if counter[index] != 0 { break }
    }
  }
}
