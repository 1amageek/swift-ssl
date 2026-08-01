import SwiftSSLCore

public struct AESGCM: ~Copyable, AuthenticatedCipher {
  public static let supportedKeyByteCounts = [16, 24, 32]
  public static let nonceByteCount = 12
  public static let tagByteCount = 16

  public let keyByteCount: Int
  private let blockCipher: AESBlockCipher
  private let hashSubkey: [UInt64]

  public init(key: Span<UInt8>) throws(AEADError) {
    guard key.count == 16 || key.count == 24 || key.count == 32 else {
      throw .invalidKeyLength(expected: Self.supportedKeyByteCounts, actual: key.count)
    }
    keyByteCount = key.count
    let blockCipher = AESBlockCipher(key: key)

    let zero = [UInt8](repeating: 0, count: 16)
    var hash = [UInt8](repeating: 0, count: 16)
    defer {
      hash.withUnsafeBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else {
          return
        }
        SecureWipe.erase(
          UnsafeMutableRawPointer(mutating: baseAddress),
          byteCount: buffer.count
        )
      }
    }
    zero.withUnsafeBufferPointer { input in
      hash.withUnsafeMutableBufferPointer { output in
        let inputSpan = Span(_unsafeElements: input)
        var outputSpan = MutableSpan(_unsafeElements: output)
        blockCipher.encrypt(inputSpan, into: &outputSpan)
      }
    }
    let hashPair = Self.readPair(hash)
    self.blockCipher = blockCipher
    hashSubkey = [hashPair.0, hashPair.1]
  }

  deinit {
    // The noncopyable owner is being destroyed, so this immutable view is
    // uniquely owned for the wipe.
    hashSubkey.withUnsafeBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else {
        return
      }
      SecureWipe.erase(
        UnsafeMutableRawPointer(mutating: baseAddress),
        byteCount: buffer.count * MemoryLayout<UInt64>.stride
      )
    }
  }

  public mutating func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    guard nonce.count == Self.nonceByteCount else {
      throw .invalidNonceLength(expected: Self.nonceByteCount, actual: nonce.count)
    }
    guard Self.validMessageLength(plaintext.count), Self.validMessageLength(authenticatedData.count)
    else {
      throw .messageLimitReached
    }
    let (required, overflow) = plaintext.count.addingReportingOverflow(Self.tagByteCount)
    guard !overflow else {
      throw .messageLimitReached
    }
    guard output.count >= required else {
      throw .outputTooSmall(required: required, actual: output.count)
    }
    guard !Self.overlaps(plaintext, output, allowSameStart: true),
      !Self.overlaps(authenticatedData, output, allowSameStart: false)
    else {
      throw .overlappingInputAndOutput
    }

    var counter = Self.j0(nonce)
    Self.incrementCounter(&counter)
    gctr(plaintext, counter: counter, into: &output)

    let tag = authenticationTag(
      authenticatedData: authenticatedData,
      ciphertext: output.span.extracting(0..<plaintext.count),
      initialCounter: Self.j0(nonce)
    )
    var index = 0
    while index < Self.tagByteCount {
      output[plaintext.count + index] = tag[index]
      index += 1
    }
  }

  public mutating func open(
    ciphertextAndTag: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    guard nonce.count == Self.nonceByteCount else {
      throw .invalidNonceLength(expected: Self.nonceByteCount, actual: nonce.count)
    }
    guard ciphertextAndTag.count >= Self.tagByteCount else {
      throw .outputTooSmall(required: Self.tagByteCount, actual: ciphertextAndTag.count)
    }
    let ciphertextCount = ciphertextAndTag.count - Self.tagByteCount
    guard output.count >= ciphertextCount else {
      throw .outputTooSmall(required: ciphertextCount, actual: output.count)
    }
    guard Self.validMessageLength(ciphertextCount), Self.validMessageLength(authenticatedData.count)
    else {
      throw .messageLimitReached
    }
    guard !Self.overlaps(ciphertextAndTag, output, allowSameStart: true),
      !Self.overlaps(authenticatedData, output, allowSameStart: false)
    else {
      throw .overlappingInputAndOutput
    }

    let ciphertext = ciphertextAndTag.extracting(0..<ciphertextCount)
    let tag = ciphertextAndTag.extracting(ciphertextCount..<ciphertextAndTag.count)
    let calculated = authenticationTag(
      authenticatedData: authenticatedData,
      ciphertext: ciphertext,
      initialCounter: Self.j0(nonce)
    )
    let valid = calculated.withUnsafeBufferPointer { calculatedBuffer in
      ConstantTime.equal(Span(_unsafeElements: calculatedBuffer), tag)
    }
    guard valid else {
      throw .authenticationFailed
    }

    var counter = Self.j0(nonce)
    Self.incrementCounter(&counter)
    gctr(ciphertext, counter: counter, into: &output)
  }

  private func gctr(
    _ input: Span<UInt8>,
    counter: [UInt8],
    into output: inout MutableSpan<UInt8>
  ) {
    var counter = counter
    var offset = 0
    var encryptedCounter = [UInt8](repeating: 0, count: 16)
    while offset < input.count {
      counter.withUnsafeBufferPointer { counterBuffer in
        encryptedCounter.withUnsafeMutableBufferPointer { outputBuffer in
          let counterSpan = Span(_unsafeElements: counterBuffer)
          var encryptedSpan = MutableSpan(_unsafeElements: outputBuffer)
          blockCipher.encrypt(counterSpan, into: &encryptedSpan)
        }
      }
      let remaining = min(16, input.count - offset)
      var index = 0
      while index < remaining {
        output[offset + index] = input[offset + index] ^ encryptedCounter[index]
        index += 1
      }
      offset += remaining
      Self.incrementCounter(&counter)
    }
  }

  private func authenticationTag(
    authenticatedData: Span<UInt8>,
    ciphertext: Span<UInt8>,
    initialCounter: [UInt8]
  ) -> [UInt8] {
    let hash = ghash(authenticatedData: authenticatedData, ciphertext: ciphertext)
    var encryptedCounter = [UInt8](repeating: 0, count: 16)
    initialCounter.withUnsafeBufferPointer { counterBuffer in
      encryptedCounter.withUnsafeMutableBufferPointer { outputBuffer in
        let counterSpan = Span(_unsafeElements: counterBuffer)
        var encryptedSpan = MutableSpan(_unsafeElements: outputBuffer)
        blockCipher.encrypt(counterSpan, into: &encryptedSpan)
      }
    }
    var result = [UInt8](repeating: 0, count: 16)
    Self.writePair(
      hash.0 ^ Self.readUInt64(encryptedCounter, offset: 0),
      hash.1 ^ Self.readUInt64(encryptedCounter, offset: 8), into: &result)
    return result
  }

  private func ghash(authenticatedData: Span<UInt8>, ciphertext: Span<UInt8>) -> (UInt64, UInt64) {
    var accumulator: (UInt64, UInt64) = (0, 0)
    accumulator = updateGHASH(accumulator, bytes: authenticatedData)
    accumulator = updateGHASH(accumulator, bytes: ciphertext)

    var lengths = [UInt8](repeating: 0, count: 16)
    Self.writeUInt64(UInt64(authenticatedData.count) * 8, into: &lengths, offset: 0)
    Self.writeUInt64(UInt64(ciphertext.count) * 8, into: &lengths, offset: 8)
    lengths.withUnsafeBufferPointer { lengthBuffer in
      accumulator = multiply(
        accumulator.0 ^ Self.readUInt64(lengthBuffer, offset: 0),
        accumulator.1 ^ Self.readUInt64(lengthBuffer, offset: 8)
      )
    }
    return accumulator
  }

  private func updateGHASH(
    _ accumulator: (UInt64, UInt64),
    bytes: Span<UInt8>
  ) -> (UInt64, UInt64) {
    var result = accumulator
    var offset = 0
    while offset < bytes.count {
      var block = [UInt8](repeating: 0, count: 16)
      let count = min(16, bytes.count - offset)
      var index = 0
      while index < count {
        block[index] = bytes[offset + index]
        index += 1
      }
      block.withUnsafeBufferPointer { blockBuffer in
        result = multiply(
          result.0 ^ Self.readUInt64(blockBuffer, offset: 0),
          result.1 ^ Self.readUInt64(blockBuffer, offset: 8)
        )
      }
      offset += count
    }
    return result
  }

  private func multiply(_ xHi: UInt64, _ xLo: UInt64) -> (UInt64, UInt64) {
    var zHi: UInt64 = 0
    var zLo: UInt64 = 0
    var vHi = hashSubkey[0]
    var vLo = hashSubkey[1]
    var bit = 0
    while bit < 128 {
      let selected =
        bit < 64
        ? ((xHi >> UInt64(63 - bit)) & 1)
        : ((xLo >> UInt64(127 - bit)) & 1)
      if selected != 0 {
        zHi ^= vHi
        zLo ^= vLo
      }
      let leastSignificantBit = vLo & 1
      vLo = (vLo >> 1) | (vHi << 63)
      vHi >>= 1
      if leastSignificantBit != 0 {
        vHi ^= 0xe100_0000_0000_0000
      }
      bit += 1
    }
    return (zHi, zLo)
  }

  private static func j0(_ nonce: Span<UInt8>) -> [UInt8] {
    var counter = [UInt8](repeating: 0, count: 16)
    var index = 0
    while index < nonce.count {
      counter[index] = nonce[index]
      index += 1
    }
    counter[15] = 1
    return counter
  }

  private static func incrementCounter(_ counter: inout [UInt8]) {
    var index = 15
    while index >= 12 {
      counter[index] &+= 1
      if counter[index] != 0 {
        break
      }
      index -= 1
    }
  }

  private static func validMessageLength(_ count: Int) -> Bool {
    count >= 0 && UInt64(count) <= ((UInt64(1) << 39) - 256)
  }

  // Unsafe boundary invariants:
  // - Both spans borrow initialized UInt8 storage for this call only.
  // - The raw ranges are read without rebinding or mutation.
  // - Address addition is checked before range comparison.
  // - The only permitted overlap is an exact input start for in-place GCTR;
  //   authenticated data never overlaps output.
  private static func overlaps(
    _ input: Span<UInt8>,
    _ output: borrowing MutableSpan<UInt8>,
    allowSameStart: Bool
  ) -> Bool {
    input.withUnsafeBytes { inputBytes in
      output.withUnsafeBytes { outputBytes in
        guard inputBytes.count > 0, outputBytes.count > 0,
          let inputBase = inputBytes.baseAddress,
          let outputBase = outputBytes.baseAddress
        else {
          return false
        }
        let inputStart = UInt(bitPattern: inputBase)
        let outputStart = UInt(bitPattern: outputBase)
        if allowSameStart && inputStart == outputStart {
          return false
        }
        let (inputEnd, inputOverflow) = inputStart.addingReportingOverflow(UInt(inputBytes.count))
        let (outputEnd, outputOverflow) = outputStart.addingReportingOverflow(
          UInt(outputBytes.count))
        guard !inputOverflow, !outputOverflow else {
          return true
        }
        return inputStart < outputEnd && outputStart < inputEnd
      }
    }
  }

  private static func readPair(_ bytes: [UInt8]) -> (UInt64, UInt64) {
    (readUInt64(bytes, offset: 0), readUInt64(bytes, offset: 8))
  }

  private static func readUInt64<B: Collection>(_ bytes: B, offset: Int) -> UInt64
  where B.Element == UInt8 {
    var result: UInt64 = 0
    var index = 0
    while index < 8 {
      result =
        (result << 8) | UInt64(bytes[bytes.index(bytes.startIndex, offsetBy: offset + index)])
      index += 1
    }
    return result
  }

  private static func writeUInt64(_ value: UInt64, into bytes: inout [UInt8], offset: Int) {
    var index = 0
    while index < 8 {
      bytes[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(56 - index * 8))
      index += 1
    }
  }

  private static func writePair(_ high: UInt64, _ low: UInt64, into bytes: inout [UInt8]) {
    writeUInt64(high, into: &bytes, offset: 0)
    writeUInt64(low, into: &bytes, offset: 8)
  }
}
