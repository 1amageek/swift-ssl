import SwiftSSLCore

public struct AESGCM: ~Copyable, AuthenticatedCipher {
  public static let supportedKeyByteCounts = [16, 24, 32]
  public static let nonceByteCount = 12
  public static let tagByteCount = 16

  public let keyByteCount: Int
  private var blockCipher: AESBlockCipher
  private var hashBasis: SIMD8<UInt64>

  public init(key: Span<UInt8>) throws(AEADError) {
    guard key.count == 16 || key.count == 24 || key.count == 32 else {
      throw .invalidKeyLength(expected: Self.supportedKeyByteCounts, actual: key.count)
    }
    keyByteCount = key.count
    let blockCipher = AESBlockCipher(key: key)

    var zero = SIMD16<UInt8>(repeating: 0)
    var hash = SIMD16<UInt8>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &hash) { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        SecureWipe.erase(baseAddress, byteCount: bytes.count)
      }
    }
    withUnsafeBytes(of: &zero) { input in
      withUnsafeMutableBytes(of: &hash) { output in
        let inputSpan = Span(
          _unsafeElements: input.bindMemory(to: UInt8.self)
        )
        var outputSpan = MutableSpan(
          _unsafeElements: output.bindMemory(to: UInt8.self)
        )
        blockCipher.encrypt(inputSpan, into: &outputSpan)
      }
    }
    let hashPair = Self.readPair(hash)
    self.blockCipher = blockCipher
    hashBasis = Self.makeHashBasis(high: hashPair.0, low: hashPair.1)
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
    var calculated = authenticationTag(
      authenticatedData: authenticatedData,
      ciphertext: ciphertext,
      initialCounter: Self.j0(nonce)
    )
    let valid = withUnsafeBytes(of: &calculated) { calculatedBuffer in
      ConstantTime.equal(
        Span(_unsafeElements: calculatedBuffer.bindMemory(to: UInt8.self)),
        tag
      )
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
    counter: SIMD16<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) {
    var counter = counter
    var offset = 0
    #if canImport(Darwin) && arch(arm64) && canImport(simd)
      while offset + 64 <= input.count {
        blockCipher.xorFourCounters(
          input,
          at: offset,
          startingAt: counter,
          into: &output
        )
        offset += 64
        Self.incrementCounter(&counter)
        Self.incrementCounter(&counter)
        Self.incrementCounter(&counter)
        Self.incrementCounter(&counter)
      }
    #endif
    var encryptedCounter = SIMD16<UInt8>(repeating: 0)
    while offset < input.count {
      withUnsafeBytes(of: &counter) { counterBuffer in
        withUnsafeMutableBytes(of: &encryptedCounter) { outputBuffer in
          let counterSpan = Span(
            _unsafeElements: counterBuffer.bindMemory(to: UInt8.self)
          )
          var encryptedSpan = MutableSpan(
            _unsafeElements: outputBuffer.bindMemory(to: UInt8.self)
          )
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
    initialCounter: SIMD16<UInt8>
  ) -> SIMD16<UInt8> {
    let hash = ghash(authenticatedData: authenticatedData, ciphertext: ciphertext)
    var initialCounter = initialCounter
    var encryptedCounter = SIMD16<UInt8>(repeating: 0)
    withUnsafeBytes(of: &initialCounter) { counterBuffer in
      withUnsafeMutableBytes(of: &encryptedCounter) { outputBuffer in
        let counterSpan = Span(
          _unsafeElements: counterBuffer.bindMemory(to: UInt8.self)
        )
        var encryptedSpan = MutableSpan(
          _unsafeElements: outputBuffer.bindMemory(to: UInt8.self)
        )
        blockCipher.encrypt(counterSpan, into: &encryptedSpan)
      }
    }
    var result = SIMD16<UInt8>(repeating: 0)
    let encryptedPair = Self.readPair(encryptedCounter)
    Self.writePair(
      hash.0 ^ encryptedPair.0,
      hash.1 ^ encryptedPair.1,
      into: &result
    )
    return result
  }

  private func ghash(authenticatedData: Span<UInt8>, ciphertext: Span<UInt8>) -> (UInt64, UInt64) {
    var accumulator: (UInt64, UInt64) = (0, 0)
    accumulator = updateGHASH(accumulator, bytes: authenticatedData)
    accumulator = updateGHASH(accumulator, bytes: ciphertext)

    accumulator = multiply(
      accumulator.0 ^ UInt64(authenticatedData.count) * 8,
      accumulator.1 ^ UInt64(ciphertext.count) * 8
    )
    return accumulator
  }

  private func updateGHASH(
    _ accumulator: (UInt64, UInt64),
    bytes: Span<UInt8>
  ) -> (UInt64, UInt64) {
    var result = accumulator
    var offset = 0
    #if canImport(Darwin) && arch(arm64) && canImport(simd) && !SWIFT_SSL_PORTABLE_GHASH
      while offset + 64 <= bytes.count {
        let block1 = Self.readPartialPair(bytes, offset: offset, count: 16)
        let block2 = Self.readPartialPair(bytes, offset: offset + 16, count: 16)
        let block3 = Self.readPartialPair(bytes, offset: offset + 32, count: 16)
        let block4 = Self.readPartialPair(bytes, offset: offset + 48, count: 16)
        result = GHASHARM64Kernel.multiplyFour(
          accumulatorHigh: result.0,
          accumulatorLow: result.1,
          blocks: SIMD8(
            block1.0, block1.1,
            block2.0, block2.1,
            block3.0, block3.1,
            block4.0, block4.1
          ),
          hashPowers: hashBasis
        )
        offset += 64
      }
    #endif
    while offset < bytes.count {
      let count = min(16, bytes.count - offset)
      let block = Self.readPartialPair(bytes, offset: offset, count: count)
      result = multiply(result.0 ^ block.0, result.1 ^ block.1)
      offset += count
    }
    return result
  }

  private func multiply(_ xHi: UInt64, _ xLo: UInt64) -> (UInt64, UInt64) {
    #if canImport(Darwin) && arch(arm64) && canImport(simd) && !SWIFT_SSL_PORTABLE_GHASH
      return GHASHARM64Kernel.multiply(
        xHigh: xHi,
        xLow: xLo,
        hashHigh: hashBasis[0],
        hashLow: hashBasis[1]
      )
    #else
      let basis = hashBasis
      var zHi: UInt64 = 0
      var zLo: UInt64 = 0
      var nibbleIndex = 0
      while nibbleIndex < 32 {
        let shifted = Self.multiplyByX4(high: zHi, low: zLo)
        zHi = shifted.0
        zLo = shifted.1

        let nibble: UInt64
        if nibbleIndex < 16 {
          nibble = (xLo >> UInt64(nibbleIndex * 4)) & 0x0F
        } else {
          nibble = (xHi >> UInt64((nibbleIndex - 16) * 4)) & 0x0F
        }
        let bit3 = UInt64(0) &- ((nibble >> 3) & 1)
        let bit2 = UInt64(0) &- ((nibble >> 2) & 1)
        let bit1 = UInt64(0) &- ((nibble >> 1) & 1)
        let bit0 = UInt64(0) &- (nibble & 1)
        zHi ^=
          (basis[0] & bit3) ^ (basis[2] & bit2)
          ^ (basis[4] & bit1) ^ (basis[6] & bit0)
        zLo ^=
          (basis[1] & bit3) ^ (basis[3] & bit2)
          ^ (basis[5] & bit1) ^ (basis[7] & bit0)
        nibbleIndex += 1
      }
      return (zHi, zLo)
    #endif
  }

  private static func makeHashBasis(
    high: UInt64,
    low: UInt64
  ) -> SIMD8<UInt64> {
    #if canImport(Darwin) && arch(arm64) && canImport(simd) && !SWIFT_SSL_PORTABLE_GHASH
      let squared = GHASHARM64Kernel.multiply(
        xHigh: high,
        xLow: low,
        hashHigh: high,
        hashLow: low
      )
      let cubed = GHASHARM64Kernel.multiply(
        xHigh: squared.0,
        xLow: squared.1,
        hashHigh: high,
        hashLow: low
      )
      let fourth = GHASHARM64Kernel.multiply(
        xHigh: squared.0,
        xLow: squared.1,
        hashHigh: squared.0,
        hashLow: squared.1
      )
      return SIMD8(high, low, squared.0, squared.1, cubed.0, cubed.1, fourth.0, fourth.1)
    #else
      let one = multiplyByX(high: high, low: low)
      let two = multiplyByX(high: one.0, low: one.1)
      let three = multiplyByX(high: two.0, low: two.1)
      return SIMD8(high, low, one.0, one.1, two.0, two.1, three.0, three.1)
    #endif
  }

  private static func multiplyByX(
    high: UInt64,
    low: UInt64
  ) -> (UInt64, UInt64) {
    let reductionMask = UInt64(0) &- (low & 1)
    return (
      (high >> 1) ^ (0xe100_0000_0000_0000 & reductionMask),
      (low >> 1) | (high << 63)
    )
  }

  private static func multiplyByX4(
    high: UInt64,
    low: UInt64
  ) -> (UInt64, UInt64) {
    let discarded = low & 0x0F
    var reduction: UInt64 = 0
    reduction ^= 0x1c20_0000_0000_0000 & (UInt64(0) &- (discarded & 1))
    reduction ^= 0x3840_0000_0000_0000 & (UInt64(0) &- ((discarded >> 1) & 1))
    reduction ^= 0x7080_0000_0000_0000 & (UInt64(0) &- ((discarded >> 2) & 1))
    reduction ^= 0xe100_0000_0000_0000 & (UInt64(0) &- ((discarded >> 3) & 1))
    return ((high >> 4) ^ reduction, (low >> 4) | (high << 60))
  }

  private static func j0(_ nonce: Span<UInt8>) -> SIMD16<UInt8> {
    var counter = SIMD16<UInt8>(repeating: 0)
    var index = 0
    while index < nonce.count {
      counter[index] = nonce[index]
      index += 1
    }
    counter[15] = 1
    return counter
  }

  private static func incrementCounter(_ counter: inout SIMD16<UInt8>) {
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

  private static func readPair(_ bytes: SIMD16<UInt8>) -> (UInt64, UInt64) {
    var high: UInt64 = 0
    var low: UInt64 = 0
    var index = 0
    while index < 8 {
      high = (high << 8) | UInt64(bytes[index])
      low = (low << 8) | UInt64(bytes[index + 8])
      index += 1
    }
    return (high, low)
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

  private static func readPartialPair(
    _ bytes: Span<UInt8>,
    offset: Int,
    count: Int
  ) -> (UInt64, UInt64) {
    if count == 16 {
      precondition(offset >= 0 && offset <= bytes.count - 16)
      // Unsafe boundary invariants:
      // - The precondition proves that both eight-byte loads are contained in
      //   initialized storage owned by `bytes` for this synchronous borrow.
      // - Unaligned loads do not bind or mutate the source allocation.
      // - The pointer does not escape or cross a Sendable boundary.
      return bytes.withUnsafeBytes { buffer in
        let baseAddress = buffer.baseAddress.unsafelyUnwrapped.advanced(by: offset)
        return (
          baseAddress.loadUnaligned(as: UInt64.self).byteSwapped,
          baseAddress.loadUnaligned(fromByteOffset: 8, as: UInt64.self).byteSwapped
        )
      }
    }
    var high: UInt64 = 0
    var low: UInt64 = 0
    var index = 0
    while index < min(count, 8) {
      high |= UInt64(bytes[offset + index]) << UInt64(56 - index * 8)
      index += 1
    }
    while index < count {
      low |= UInt64(bytes[offset + index]) << UInt64(120 - index * 8)
      index += 1
    }
    return (high, low)
  }

  private static func writeUInt64(
    _ value: UInt64,
    into bytes: inout SIMD16<UInt8>,
    offset: Int
  ) {
    var index = 0
    while index < 8 {
      bytes[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(56 - index * 8))
      index += 1
    }
  }

  private static func writePair(
    _ high: UInt64,
    _ low: UInt64,
    into bytes: inout SIMD16<UInt8>
  ) {
    writeUInt64(high, into: &bytes, offset: 0)
    writeUInt64(low, into: &bytes, offset: 8)
  }

  deinit {
    // Unsafe boundary invariants:
    // - AESGCM is noncopyable, so destruction wipes its unique inline state
    //   exactly once after blockCipher has completed all borrows.
    // - All eight UInt64 lanes are initialized and exclusively mutable here.
    // - The pointer is scoped to this closure and never crosses concurrency.
    // deinit exposes self immutably, but the noncopyable value has no live
    // alias; the scoped mutating raw pointer is used only for the final wipe.
    withUnsafeBytes(of: hashBasis) { bytes in
      guard let baseAddress = bytes.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(mutating: baseAddress),
        byteCount: bytes.count
      )
    }
  }
}
