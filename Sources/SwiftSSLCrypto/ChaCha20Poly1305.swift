import SwiftSSLCore

/// RFC 8439 ChaCha20-Poly1305.
///
/// The public API borrows input spans and writes into caller-owned storage. No
/// pointer escapes a scoped buffer closure. The reference implementation uses
/// bounded 64-byte and 16-byte temporaries; the allocation/code-generation
/// budget is tracked separately from the correctness contract.
public struct ChaCha20Poly1305: ~Copyable, AuthenticatedCipher {
  public static let supportedKeyByteCounts = [32]
  public static let nonceByteCount = 12
  public static let tagByteCount = 16

  private let keyWords: [UInt32]

  public init(key: Span<UInt8>) throws(AEADError) {
    guard key.count == 32 else {
      throw .invalidKeyLength(expected: Self.supportedKeyByteCounts, actual: key.count)
    }
    var words = [UInt32](repeating: 0, count: 8)
    var index = 0
    while index < words.count {
      words[index] = Self.readUInt32LittleEndian(key, offset: index * 4)
      index += 1
    }
    keyWords = words
  }

  deinit {
    // This noncopyable owner is destroyed here. The immutable buffer is
    // uniquely owned for the duration of the wipe and never escapes.
    keyWords.withUnsafeBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(mutating: baseAddress),
        byteCount: buffer.count * MemoryLayout<UInt32>.stride
      )
    }
  }

  public mutating func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    try validate(
      messageByteCount: plaintext.count,
      authenticatedDataByteCount: authenticatedData.count,
      nonce: nonce,
      outputByteCount: output.count,
      includesTag: true
    )
    guard !Self.overlaps(plaintext, output, allowSameStart: true),
      !Self.overlaps(authenticatedData, output, allowSameStart: false)
    else {
      throw .overlappingInputAndOutput
    }

    crypt(plaintext, nonce: nonce, initialCounter: 1, into: &output)
    // End the read borrow before opening the mutable output access below.
    var tag = output.withUnsafeBytes { rawBytes in
      guard let baseAddress = rawBytes.baseAddress else {
        return authenticationTag(
          authenticatedData: authenticatedData,
          ciphertext: Span(_unsafeElements: UnsafeBufferPointer(start: nil, count: 0)),
          nonce: nonce
        )
      }
      let pointer = UnsafeBufferPointer(
        start: baseAddress.assumingMemoryBound(to: UInt8.self),
        count: plaintext.count
      )
      return authenticationTag(
        authenticatedData: authenticatedData,
        ciphertext: Span(_unsafeElements: pointer),
        nonce: nonce
      )
    }
    defer { Self.wipe(&tag) }
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
    guard ciphertextAndTag.count >= Self.tagByteCount else {
      throw .outputTooSmall(required: Self.tagByteCount, actual: ciphertextAndTag.count)
    }
    let ciphertextByteCount = ciphertextAndTag.count - Self.tagByteCount
    try validate(
      messageByteCount: ciphertextByteCount,
      authenticatedDataByteCount: authenticatedData.count,
      nonce: nonce,
      outputByteCount: output.count,
      includesTag: false
    )
    guard !Self.overlaps(ciphertextAndTag, output, allowSameStart: true),
      !Self.overlaps(authenticatedData, output, allowSameStart: false)
    else {
      throw .overlappingInputAndOutput
    }

    let ciphertext = ciphertextAndTag.extracting(0..<ciphertextByteCount)
    let tag = ciphertextAndTag.extracting(ciphertextByteCount..<ciphertextAndTag.count)
    var calculated = authenticationTag(
      authenticatedData: authenticatedData,
      ciphertext: ciphertext,
      nonce: nonce
    )
    defer { Self.wipe(&calculated) }
    let valid = calculated.withUnsafeBufferPointer { buffer in
      ConstantTime.equal(Span(_unsafeElements: buffer), tag)
    }
    guard valid else {
      // Authentication is checked before any plaintext is written.
      throw .authenticationFailed
    }
    crypt(ciphertext, nonce: nonce, initialCounter: 1, into: &output)
  }

  private func validate(
    messageByteCount: Int,
    authenticatedDataByteCount: Int,
    nonce: Span<UInt8>,
    outputByteCount: Int,
    includesTag: Bool
  ) throws(AEADError) {
    guard nonce.count == Self.nonceByteCount else {
      throw .invalidNonceLength(expected: Self.nonceByteCount, actual: nonce.count)
    }
    guard Self.validMessageLength(messageByteCount),
      Self.validLength(authenticatedDataByteCount)
    else {
      throw .messageLimitReached
    }
    let (required, overflow) = messageByteCount.addingReportingOverflow(
      includesTag ? Self.tagByteCount : 0
    )
    guard !overflow else { throw .messageLimitReached }
    guard outputByteCount >= required else {
      throw .outputTooSmall(required: required, actual: outputByteCount)
    }
  }

  private func authenticationTag(
    authenticatedData: Span<UInt8>,
    ciphertext: Span<UInt8>,
    nonce: Span<UInt8>
  ) -> [UInt8] {
    var oneTimeKey = Self.chachaBlock(counter: 0, nonce: nonce, keyWords: keyWords)
    defer { Self.wipe(&oneTimeKey) }
    var poly1305: Poly1305!
    oneTimeKey.withUnsafeBufferPointer { buffer in
      poly1305 = Poly1305(key: Span(_unsafeElements: buffer))
    }
    poly1305.update(authenticatedData)
    poly1305.padToBlock()
    poly1305.update(ciphertext)
    poly1305.padToBlock()

    var lengths = [UInt8](repeating: 0, count: 16)
    // RFC 8439 encodes the original byte lengths, unlike GCM which uses
    // bit lengths. The fields are little-endian UInt64 values.
    Self.writeUInt64LittleEndian(UInt64(authenticatedData.count), into: &lengths, offset: 0)
    Self.writeUInt64LittleEndian(UInt64(ciphertext.count), into: &lengths, offset: 8)
    lengths.withUnsafeBufferPointer { buffer in
      poly1305.update(Span(_unsafeElements: buffer))
    }
    Self.wipe(&lengths)
    return poly1305.finalize()
  }

  private func crypt(
    _ input: Span<UInt8>,
    nonce: Span<UInt8>,
    initialCounter: UInt32,
    into output: inout MutableSpan<UInt8>
  ) {
    var counter = initialCounter
    var offset = 0
    while offset < input.count {
      var block = Self.chachaBlock(counter: counter, nonce: nonce, keyWords: keyWords)
      defer { Self.wipe(&block) }
      let count = min(64, input.count - offset)
      var index = 0
      while index < count {
        output[offset + index] = input[offset + index] ^ block[index]
        index += 1
      }
      offset += count
      counter &+= 1
    }
  }

  private static func chachaBlock(
    counter: UInt32,
    nonce: Span<UInt8>,
    keyWords: [UInt32]
  ) -> [UInt8] {
    var state = [UInt32](repeating: 0, count: 16)
    state[0] = 0x6170_7865
    state[1] = 0x3320_646e
    state[2] = 0x7962_2d32
    state[3] = 0x6b20_6574
    var index = 0
    while index < 8 {
      state[4 + index] = keyWords[index]
      index += 1
    }
    state[12] = counter
    state[13] = readUInt32LittleEndian(nonce, offset: 0)
    state[14] = readUInt32LittleEndian(nonce, offset: 4)
    state[15] = readUInt32LittleEndian(nonce, offset: 8)

    var working = state
    var round = 0
    while round < 10 {
      quarterRound(&working, 0, 4, 8, 12)
      quarterRound(&working, 1, 5, 9, 13)
      quarterRound(&working, 2, 6, 10, 14)
      quarterRound(&working, 3, 7, 11, 15)
      quarterRound(&working, 0, 5, 10, 15)
      quarterRound(&working, 1, 6, 11, 12)
      quarterRound(&working, 2, 7, 8, 13)
      quarterRound(&working, 3, 4, 9, 14)
      round += 1
    }

    var output = [UInt8](repeating: 0, count: 64)
    index = 0
    while index < 16 {
      writeUInt32LittleEndian(working[index] &+ state[index], into: &output, offset: index * 4)
      index += 1
    }
    wipeWords(&state)
    wipeWords(&working)
    return output
  }

  @inline(__always)
  private static func quarterRound(
    _ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int
  ) {
    state[a] &+= state[b]
    state[d] = rotateLeft(state[d] ^ state[a], by: 16)
    state[c] &+= state[d]
    state[b] = rotateLeft(state[b] ^ state[c], by: 12)
    state[a] &+= state[b]
    state[d] = rotateLeft(state[d] ^ state[a], by: 8)
    state[c] &+= state[d]
    state[b] = rotateLeft(state[b] ^ state[c], by: 7)
  }

  @inline(__always)
  private static func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
    (value << amount) | (value >> (32 - amount))
  }

  private static func validMessageLength(_ count: Int) -> Bool {
    count >= 0 && UInt64(count) <= UInt64(UInt32.max) * 64
  }

  private static func validLength(_ count: Int) -> Bool {
    count >= 0 && UInt64(count) <= UInt64.max / 8
  }

  // Unsafe boundary invariants:
  // - Input and output spans borrow initialized UInt8 storage only for this call.
  // - Raw addresses are inspected but never rebound or retained.
  // - Address addition is checked before range comparison.
  // - Exact same-start input/output is the sole supported overlap.
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
        else { return false }
        let inputStart = UInt(bitPattern: inputBase)
        let outputStart = UInt(bitPattern: outputBase)
        if allowSameStart && inputStart == outputStart { return false }
        let (inputEnd, inputOverflow) = inputStart.addingReportingOverflow(UInt(inputBytes.count))
        let (outputEnd, outputOverflow) = outputStart.addingReportingOverflow(
          UInt(outputBytes.count))
        guard !inputOverflow, !outputOverflow else { return true }
        return inputStart < outputEnd && outputStart < inputEnd
      }
    }
  }

  fileprivate static func readUInt32LittleEndian(_ bytes: Span<UInt8>, offset: Int) -> UInt32 {
    UInt32(bytes[offset])
      | (UInt32(bytes[offset + 1]) << 8)
      | (UInt32(bytes[offset + 2]) << 16)
      | (UInt32(bytes[offset + 3]) << 24)
  }

  fileprivate static func writeUInt32LittleEndian(
    _ value: UInt32, into bytes: inout [UInt8], offset: Int
  ) {
    bytes[offset] = UInt8(truncatingIfNeeded: value)
    bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
    bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
    bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
  }

  fileprivate static func readUInt64LittleEndian(_ bytes: Span<UInt8>, offset: Int) -> UInt64 {
    var value: UInt64 = 0
    var index = 0
    while index < 8 {
      value |= UInt64(bytes[offset + index]) << UInt64(index * 8)
      index += 1
    }
    return value
  }

  fileprivate static func writeUInt64LittleEndian(
    _ value: UInt64, into bytes: inout [UInt8], offset: Int
  ) {
    var index = 0
    while index < 8 {
      bytes[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(index * 8))
      index += 1
    }
  }

  fileprivate static func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
    }
  }

  private static func wipeWords(_ words: inout [UInt32]) {
    words.withUnsafeMutableBufferPointer { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      SecureWipe.erase(
        UnsafeMutableRawPointer(baseAddress),
        byteCount: buffer.count * MemoryLayout<UInt32>.stride
      )
    }
  }
}

/// Stable owner for Poly1305 state. A class is used so secret state has one
/// identity and can be wiped from deinit without noncopyable struct mutation
/// restrictions. It is never sent across concurrency boundaries.
private final class Poly1305 {
  private var r0: UInt64
  private var r1: UInt64
  private var r2: UInt64
  private var r3: UInt64
  private var r4: UInt64
  private var h0: UInt64 = 0
  private var h1: UInt64 = 0
  private var h2: UInt64 = 0
  private var h3: UInt64 = 0
  private var h4: UInt64 = 0
  private var pad0: UInt64
  private var pad1: UInt64
  private var buffer = [UInt8](repeating: 0, count: 16)
  private var bufferCount = 0

  init(key: Span<UInt8>) {
    let t0 = ChaCha20Poly1305.readUInt32LittleEndian(key, offset: 0)
    let t1 = ChaCha20Poly1305.readUInt32LittleEndian(key, offset: 4)
    let t2 = ChaCha20Poly1305.readUInt32LittleEndian(key, offset: 8)
    let t3 = ChaCha20Poly1305.readUInt32LittleEndian(key, offset: 12)
    r0 = UInt64(t0) & 0x3ffffff
    r1 = UInt64((t0 >> 26) | (t1 << 6)) & 0x3ffff03
    r2 = UInt64((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff
    r3 = UInt64((t2 >> 14) | (t3 << 18)) & 0x3f03fff
    r4 = UInt64(t3 >> 8) & 0x00fffff
    pad0 = ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 16)
    pad1 = ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 24)
  }

  deinit {
    wipe(&r0)
    wipe(&r1)
    wipe(&r2)
    wipe(&r3)
    wipe(&r4)
    wipe(&h0)
    wipe(&h1)
    wipe(&h2)
    wipe(&h3)
    wipe(&h4)
    wipe(&pad0)
    wipe(&pad1)
    wipe(&bufferCount)
    ChaCha20Poly1305.wipe(&buffer)
  }

  func update(_ bytes: Span<UInt8>) {
    var offset = 0
    if bufferCount > 0 {
      let count = min(16 - bufferCount, bytes.count)
      var index = 0
      while index < count {
        buffer[bufferCount + index] = bytes[offset + index]
        index += 1
      }
      bufferCount += count
      offset += count
      if bufferCount == 16 {
        processFullBlock()
        bufferCount = 0
      }
    }
    while offset + 16 <= bytes.count {
      var block = [UInt8](repeating: 0, count: 16)
      var index = 0
      while index < 16 {
        block[index] = bytes[offset + index]
        index += 1
      }
      block.withUnsafeBufferPointer { pointer in
        processFullBlock(Span(_unsafeElements: pointer))
      }
      ChaCha20Poly1305.wipe(&block)
      offset += 16
    }
    while offset < bytes.count {
      buffer[bufferCount] = bytes[offset]
      bufferCount += 1
      offset += 1
    }
  }

  func padToBlock() {
    guard bufferCount > 0 else { return }
    while bufferCount < 16 {
      buffer[bufferCount] = 0
      bufferCount += 1
    }
    processFullBlock()
    bufferCount = 0
  }

  func finalize() -> [UInt8] {
    if bufferCount > 0 {
      var index = bufferCount
      buffer[index] = 1
      index += 1
      while index < 16 {
        buffer[index] = 0
        index += 1
      }
      processPartialBlock()
      bufferCount = 0
    }

    var carry = h1 >> 26
    h1 &= 0x3ffffff
    h2 += carry
    carry = h2 >> 26
    h2 &= 0x3ffffff
    h3 += carry
    carry = h3 >> 26
    h3 &= 0x3ffffff
    h4 += carry
    carry = h4 >> 26
    h4 &= 0x3ffffff
    h0 += carry * 5
    carry = h0 >> 26
    h0 &= 0x3ffffff
    h1 += carry

    var g0 = h0 + 5
    carry = g0 >> 26
    g0 &= 0x3ffffff
    var g1 = h1 + carry
    carry = g1 >> 26
    g1 &= 0x3ffffff
    var g2 = h2 + carry
    carry = g2 >> 26
    g2 &= 0x3ffffff
    var g3 = h3 + carry
    carry = g3 >> 26
    g3 &= 0x3ffffff
    let g4 = (h4 + carry) &- (1 << 26)
    let mask = (g4 >> 63) &- 1
    let inverseMask = ~mask
    h0 = (h0 & inverseMask) | (g0 & mask)
    h1 = (h1 & inverseMask) | (g1 & mask)
    h2 = (h2 & inverseMask) | (g2 & mask)
    h3 = (h3 & inverseMask) | (g3 & mask)
    h4 = (h4 & inverseMask) | (g4 & mask)

    let word0 = h0 | (h1 << 26) | (h2 << 52)
    let word1 = (h2 >> 12) | (h3 << 14) | (h4 << 40)
    let (low, overflow) = word0.addingReportingOverflow(pad0)
    var high = word1 &+ pad1
    if overflow { high &+= 1 }
    var result = [UInt8](repeating: 0, count: 16)
    ChaCha20Poly1305.writeUInt64LittleEndian(low, into: &result, offset: 0)
    ChaCha20Poly1305.writeUInt64LittleEndian(high, into: &result, offset: 8)
    return result
  }

  private func processFullBlock() {
    buffer.withUnsafeBufferPointer { pointer in
      processFullBlock(Span(_unsafeElements: pointer))
    }
  }

  private func processFullBlock(_ block: Span<UInt8>) {
    let t0 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 0)
    let t1 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 4)
    let t2 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 8)
    let t3 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 12)
    addAndMultiply(
      UInt64(t0) & 0x3ffffff,
      UInt64((t0 >> 26) | (t1 << 6)) & 0x3ffffff,
      UInt64((t1 >> 20) | (t2 << 12)) & 0x3ffffff,
      UInt64((t2 >> 14) | (t3 << 18)) & 0x3ffffff,
      UInt64(t3 >> 8) & 0x3ffffff,
      hibit: 1 << 24
    )
  }

  private func processPartialBlock() {
    buffer.withUnsafeBufferPointer { pointer in
      let block = Span(_unsafeElements: pointer)
      let t0 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 0)
      let t1 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 4)
      let t2 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 8)
      let t3 = ChaCha20Poly1305.readUInt32LittleEndian(block, offset: 12)
      addAndMultiply(
        UInt64(t0) & 0x3ffffff,
        UInt64((t0 >> 26) | (t1 << 6)) & 0x3ffffff,
        UInt64((t1 >> 20) | (t2 << 12)) & 0x3ffffff,
        UInt64((t2 >> 14) | (t3 << 18)) & 0x3ffffff,
        UInt64(t3 >> 8) & 0x3ffffff,
        hibit: 0
      )
    }
  }

  @inline(__always)
  private func addAndMultiply(
    _ m0: UInt64, _ m1: UInt64, _ m2: UInt64, _ m3: UInt64, _ m4: UInt64,
    hibit: UInt64
  ) {
    h0 += m0
    h1 += m1
    h2 += m2
    h3 += m3
    h4 += m4 + hibit
    let d0 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1)
    let d1 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2)
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3)
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4)
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0
    var carry = d0 >> 26
    h0 = d0 & 0x3ffffff
    var value = d1 + carry
    carry = value >> 26
    h1 = value & 0x3ffffff
    value = d2 + carry
    carry = value >> 26
    h2 = value & 0x3ffffff
    value = d3 + carry
    carry = value >> 26
    h3 = value & 0x3ffffff
    value = d4 + carry
    carry = value >> 26
    h4 = value & 0x3ffffff
    h0 += carry * 5
    carry = h0 >> 26
    h0 &= 0x3ffffff
    h1 += carry
  }

  private func wipe<T>(_ value: inout T) {
    withUnsafeMutableBytes(of: &value) { rawBytes in
      guard let baseAddress = rawBytes.baseAddress else { return }
      SecureWipe.erase(baseAddress, byteCount: rawBytes.count)
    }
  }
}
