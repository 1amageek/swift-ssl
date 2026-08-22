import SSLCore

/// RFC 8439 ChaCha20-Poly1305.
///
/// The public API borrows input spans and writes into caller-owned storage. No
/// pointer escapes a scoped buffer closure. The reference implementation uses
/// bounded 64-byte and 16-byte temporaries; the allocation/code-generation
/// budget is tracked separately from the correctness contract.
public struct ChaCha20Poly1305: ~Copyable, AuthenticatedCipher, Sendable {
  public static let supportedKeyByteCounts = [32]
  public static let nonceByteCount = 12
  public static let tagByteCount = 16

  private var keyWords: SIMD8<UInt32>

  public init(key: Span<UInt8>) throws(AEADError) {
    guard key.count == 32 else {
      throw .invalidKeyLength(expected: Self.supportedKeyByteCounts, actual: key.count)
    }
    var words = SIMD8<UInt32>(repeating: 0)
    var index = 0
    while index < 8 {
      words[index] = Self.readUInt32LittleEndian(key, offset: index * 4)
      index += 1
    }
    keyWords = words
  }

  package static func recordNumberMask(
    key: Span<UInt8>,
    sample: Span<UInt8>
  ) throws(AEADError) -> ContiguousArray<UInt8> {
    guard key.count == 32 else {
      throw .invalidKeyLength(expected: Self.supportedKeyByteCounts, actual: key.count)
    }
    guard sample.count == 16 else {
      throw .invalidNonceLength(expected: 16, actual: sample.count)
    }
    var keyWords = SIMD8<UInt32>(repeating: 0)
    defer { wipeValue(&keyWords) }
    var index = 0
    while index < 8 {
      keyWords[index] = readUInt32LittleEndian(key, offset: index * 4)
      index += 1
    }
    let counter = readUInt32LittleEndian(sample, offset: 0)
    let nonce = sample.extracting(4..<16)
    var block = chachaBlock(counter: counter, nonce: nonce, keyWords: keyWords)
    defer { wipeValue(&block) }
    var mask = ContiguousArray<UInt8>()
    mask.reserveCapacity(16)
    index = 0
    while index < 16 {
      let word = block[index >> 2]
      mask.append(UInt8(truncatingIfNeeded: word >> UInt32((index & 3) * 8)))
      index += 1
    }
    return mask
  }

  deinit {
    // Materialize the fixed-width key in scoped mutable storage for the
    // optimizer-resistant wipe. The temporary never escapes this deinitializer.
    var words = keyWords
    Self.wipeValue(&words)
  }

  /// Seals a message with a scoped move-only cipher owner.
  public static func seal(
    key: Span<UInt8>,
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    let cipher = try Self(key: key)
    try cipher.seal(
      plaintext: plaintext,
      authenticatedData: authenticatedData,
      nonce: nonce,
      into: &output
    )
  }

  /// Opens a message with a scoped move-only cipher owner.
  public static func open(
    key: Span<UInt8>,
    ciphertextAndTag: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    let cipher = try Self(key: key)
    try cipher.open(
      ciphertextAndTag: ciphertextAndTag,
      authenticatedData: authenticatedData,
      nonce: nonce,
      into: &output
    )
  }

  public func seal(
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

  /// Seals a borrowed prefix followed by one byte and zero padding directly
  /// into caller-owned ciphertext storage.
  ///
  /// This package-level framing primitive avoids materializing or copying a
  /// concatenated plaintext while preserving the same AEAD result as sealing
  /// `plaintextPrefix + [trailingByte] + zeroPadding`.
  package func sealAppendingByteAndZeroPadding(
    plaintextPrefix: Span<UInt8>,
    trailingByte: UInt8,
    zeroPaddingByteCount: Int,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    guard zeroPaddingByteCount >= 0 else {
      throw .messageLimitReached
    }
    let (prefixAndByteCount, prefixOverflow) = plaintextPrefix.count.addingReportingOverflow(1)
    let (plaintextByteCount, paddingOverflow) =
      prefixAndByteCount.addingReportingOverflow(zeroPaddingByteCount)
    guard !prefixOverflow, !paddingOverflow else {
      throw .messageLimitReached
    }
    try validate(
      messageByteCount: plaintextByteCount,
      authenticatedDataByteCount: authenticatedData.count,
      nonce: nonce,
      outputByteCount: output.count,
      includesTag: true
    )
    guard !Self.overlaps(plaintextPrefix, output, allowSameStart: false),
      !Self.overlaps(authenticatedData, output, allowSameStart: false)
    else {
      throw .overlappingInputAndOutput
    }

    cryptAppendingByteAndZeroPadding(
      plaintextPrefix,
      trailingByte: trailingByte,
      zeroPaddingByteCount: zeroPaddingByteCount,
      nonce: nonce,
      initialCounter: 1,
      into: &output
    )
    // Unsafe boundary invariants:
    // - Validation proves that output owns at least plaintextByteCount fully
    //   initialized UInt8 elements produced by the encryption step above.
    // - UInt8 has stride and alignment one; the immutable byte view is exact.
    // - The pointer and ciphertext span are borrowed only while computing the
    //   tag and cannot escape or cross a Sendable boundary.
    var tag = output.withUnsafeBytes { rawBytes in
      let baseAddress = rawBytes.baseAddress.unsafelyUnwrapped
      let pointer = UnsafeBufferPointer(
        start: baseAddress.assumingMemoryBound(to: UInt8.self),
        count: plaintextByteCount
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
      output[plaintextByteCount + index] = tag[index]
      index += 1
    }
  }

  public func open(
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
    defer { Self.wipeValue(&oneTimeKey) }
    var poly1305: Poly1305!
    withUnsafeBytes(of: &oneTimeKey) { rawBytes in
      let bytes = rawBytes.bindMemory(to: UInt8.self)
      poly1305 = Poly1305(key: Span(_unsafeElements: bytes))
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
    let nonce0 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 0))
    let nonce1 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 4))
    let nonce2 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 8))
    while offset + 256 <= input.count {
      Self.cryptFourBlocks(
        input,
        inputOffset: offset,
        counter: counter,
        nonce0: nonce0,
        nonce1: nonce1,
        nonce2: nonce2,
        keyWords: keyWords,
        into: &output
      )
      offset += 256
      counter &+= 4
    }
    while offset < input.count {
      var block = Self.chachaBlock(counter: counter, nonce: nonce, keyWords: keyWords)
      let count = min(64, input.count - offset)
      var index = 0
      while index < count {
        let word = block[index >> 2]
        let keyByte = UInt8(truncatingIfNeeded: word >> UInt32((index & 3) * 8))
        output[offset + index] = input[offset + index] ^ keyByte
        index += 1
      }
      Self.wipeValue(&block)
      offset += count
      counter &+= 1
    }
  }

  private func cryptAppendingByteAndZeroPadding(
    _ plaintextPrefix: Span<UInt8>,
    trailingByte: UInt8,
    zeroPaddingByteCount: Int,
    nonce: Span<UInt8>,
    initialCounter: UInt32,
    into output: inout MutableSpan<UInt8>
  ) {
    let plaintextByteCount = plaintextPrefix.count + 1 + zeroPaddingByteCount
    var counter = initialCounter
    var offset = 0
    let nonce0 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 0))
    let nonce1 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 4))
    let nonce2 = SIMD4<UInt32>(repeating: Self.readUInt32LittleEndian(nonce, offset: 8))
    while offset + 256 <= plaintextPrefix.count {
      Self.cryptFourBlocks(
        plaintextPrefix,
        inputOffset: offset,
        counter: counter,
        nonce0: nonce0,
        nonce1: nonce1,
        nonce2: nonce2,
        keyWords: keyWords,
        into: &output
      )
      offset += 256
      counter &+= 4
    }
    while offset < plaintextByteCount {
      var block = Self.chachaBlock(counter: counter, nonce: nonce, keyWords: keyWords)
      let count = min(64, plaintextByteCount - offset)
      var index = 0
      while index < count {
        let sourceIndex = offset + index
        let plaintextByte: UInt8
        if sourceIndex < plaintextPrefix.count {
          plaintextByte = plaintextPrefix[sourceIndex]
        } else if sourceIndex == plaintextPrefix.count {
          plaintextByte = trailingByte
        } else {
          plaintextByte = 0
        }
        let word = block[index >> 2]
        let keyByte = UInt8(truncatingIfNeeded: word >> UInt32((index & 3) * 8))
        output[sourceIndex] = plaintextByte ^ keyByte
        index += 1
      }
      Self.wipeValue(&block)
      offset += count
      counter &+= 1
    }
  }

  @inline(__always)
  private static func cryptFourBlocks(
    _ input: Span<UInt8>,
    inputOffset: Int,
    counter: UInt32,
    nonce0: SIMD4<UInt32>,
    nonce1: SIMD4<UInt32>,
    nonce2: SIMD4<UInt32>,
    keyWords: SIMD8<UInt32>,
    into output: inout MutableSpan<UInt8>
  ) {
    // Four independent ChaCha blocks occupy the SIMD lanes. Every vector is
    // fully initialized, remains in this synchronous scope, and is wiped after
    // its 256 output bytes have been written. The counter precondition follows
    // from the validated RFC 8439 message limit; wrapping is only reachable on
    // the final permitted block group.
    let constant0 = SIMD4<UInt32>(repeating: 0x6170_7865)
    let constant1 = SIMD4<UInt32>(repeating: 0x3320_646e)
    let constant2 = SIMD4<UInt32>(repeating: 0x7962_2d32)
    let constant3 = SIMD4<UInt32>(repeating: 0x6b20_6574)
    let key0 = SIMD4<UInt32>(repeating: keyWords[0])
    let key1 = SIMD4<UInt32>(repeating: keyWords[1])
    let key2 = SIMD4<UInt32>(repeating: keyWords[2])
    let key3 = SIMD4<UInt32>(repeating: keyWords[3])
    let key4 = SIMD4<UInt32>(repeating: keyWords[4])
    let key5 = SIMD4<UInt32>(repeating: keyWords[5])
    let key6 = SIMD4<UInt32>(repeating: keyWords[6])
    let key7 = SIMD4<UInt32>(repeating: keyWords[7])
    let counters = SIMD4<UInt32>(counter, counter &+ 1, counter &+ 2, counter &+ 3)
    var x0 = constant0
    var x1 = constant1
    var x2 = constant2
    var x3 = constant3
    var x4 = key0
    var x5 = key1
    var x6 = key2
    var x7 = key3
    var x8 = key4
    var x9 = key5
    var x10 = key6
    var x11 = key7
    var x12 = counters
    var x13 = nonce0
    var x14 = nonce1
    var x15 = nonce2

    var round = 0
    while round < 10 {
      quarterRound(&x0, &x4, &x8, &x12)
      quarterRound(&x1, &x5, &x9, &x13)
      quarterRound(&x2, &x6, &x10, &x14)
      quarterRound(&x3, &x7, &x11, &x15)
      quarterRound(&x0, &x5, &x10, &x15)
      quarterRound(&x1, &x6, &x11, &x12)
      quarterRound(&x2, &x7, &x8, &x13)
      quarterRound(&x3, &x4, &x9, &x14)
      round += 1
    }

    x0 &+= constant0
    x1 &+= constant1
    x2 &+= constant2
    x3 &+= constant3
    x4 &+= key0
    x5 &+= key1
    x6 &+= key2
    x7 &+= key3
    x8 &+= key4
    x9 &+= key5
    x10 &+= key6
    x11 &+= key7
    x12 &+= counters
    x13 &+= nonce0
    x14 &+= nonce1
    x15 &+= nonce2

    input.withUnsafeBytes { inputBytes in
      output.withUnsafeMutableBytes { outputBytes in
        // Unsafe boundary invariants:
        // - Validation guarantees 256 initialized input bytes and 256 writable
        //   output bytes starting at `inputOffset`.
        // - Exact same-start aliasing is supported because each 16-byte input
        //   vector is loaded before the corresponding output vector is stored.
        // - Unaligned loads do not bind source memory. Stores use typed access
        //   only for aligned addresses and byte copies otherwise.
        // - Both raw pointers are borrowed by nested synchronous closures and
        //   cannot escape; all offsets are multiples of 16 within the group.
        let inputBase = inputBytes.baseAddress.unsafelyUnwrapped
        let outputBase = outputBytes.baseAddress.unsafelyUnwrapped
        xorFourBlockWordGroup(
          x0, x1, x2, x3,
          wordGroup: 0,
          input: inputBase,
          output: outputBase,
          inputOffset: inputOffset
        )
        xorFourBlockWordGroup(
          x4, x5, x6, x7,
          wordGroup: 1,
          input: inputBase,
          output: outputBase,
          inputOffset: inputOffset
        )
        xorFourBlockWordGroup(
          x8, x9, x10, x11,
          wordGroup: 2,
          input: inputBase,
          output: outputBase,
          inputOffset: inputOffset
        )
        xorFourBlockWordGroup(
          x12, x13, x14, x15,
          wordGroup: 3,
          input: inputBase,
          output: outputBase,
          inputOffset: inputOffset
        )
      }
    }

    wipeValue(&x0)
    wipeValue(&x1)
    wipeValue(&x2)
    wipeValue(&x3)
    wipeValue(&x4)
    wipeValue(&x5)
    wipeValue(&x6)
    wipeValue(&x7)
    wipeValue(&x8)
    wipeValue(&x9)
    wipeValue(&x10)
    wipeValue(&x11)
    wipeValue(&x12)
    wipeValue(&x13)
    wipeValue(&x14)
    wipeValue(&x15)
  }

  @inline(__always)
  private static func xorFourBlockWordGroup(
    _ word0: SIMD4<UInt32>,
    _ word1: SIMD4<UInt32>,
    _ word2: SIMD4<UInt32>,
    _ word3: SIMD4<UInt32>,
    wordGroup: Int,
    input: UnsafeRawPointer,
    output: UnsafeMutableRawPointer,
    inputOffset: Int,
  ) {
    var lane = 0
    while lane < 4 {
      let offset = inputOffset + lane * 64 + wordGroup * 16
      let keyStreamWords = SIMD4<UInt32>(
        word0[lane], word1[lane], word2[lane], word3[lane]
      )
      let keyStream = unsafeBitCast(keyStreamWords, to: SIMD16<UInt8>.self)
      let inputVector = input.loadUnaligned(
        fromByteOffset: offset,
        as: SIMD16<UInt8>.self
      )
      storePossiblyUnaligned(
        inputVector ^ keyStream,
        to: output.advanced(by: offset)
      )
      lane += 1
    }
  }

  @inline(__always)
  private static func storePossiblyUnaligned(
    _ value: SIMD16<UInt8>,
    to destination: UnsafeMutableRawPointer
  ) {
    if UInt(bitPattern: destination) & UInt(MemoryLayout<SIMD16<UInt8>>.alignment - 1) == 0 {
      destination.storeBytes(of: value, as: SIMD16<UInt8>.self)
      return
    }
    var value = value
    withUnsafeBytes(of: &value) { source in
      destination.copyMemory(from: source.baseAddress.unsafelyUnwrapped, byteCount: 16)
    }
  }

  private static func chachaBlock(
    counter: UInt32,
    nonce: Span<UInt8>,
    keyWords: SIMD8<UInt32>
  ) -> SIMD16<UInt32> {
    // Fixed-width SIMD storage keeps the 16-word ChaCha state in value storage.
    // It has one initialized owner per call, is wiped before return/after use,
    // and no raw pointer or borrow escapes this function.
    var state = SIMD16<UInt32>(repeating: 0)
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

    index = 0
    while index < 16 {
      working[index] &+= state[index]
      index += 1
    }
    wipeValue(&state)
    return working
  }

  @inline(__always)
  private static func quarterRound(
    _ state: inout SIMD16<UInt32>, _ a: Int, _ b: Int, _ c: Int, _ d: Int
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
  private static func quarterRound(
    _ a: inout SIMD4<UInt32>,
    _ b: inout SIMD4<UInt32>,
    _ c: inout SIMD4<UInt32>,
    _ d: inout SIMD4<UInt32>
  ) {
    a &+= b
    d = rotateLeft(d ^ a, by: 16)
    c &+= d
    b = rotateLeft(b ^ c, by: 12)
    a &+= b
    d = rotateLeft(d ^ a, by: 8)
    c &+= d
    b = rotateLeft(b ^ c, by: 7)
  }

  @inline(__always)
  private static func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
    (value << amount) | (value >> (32 - amount))
  }

  @inline(__always)
  private static func rotateLeft(
    _ value: SIMD4<UInt32>,
    by amount: UInt32
  ) -> SIMD4<UInt32> {
    (value &<< amount) | (value &>> (32 - amount))
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

  private static func wipeValue<T>(_ value: inout T) {
    withUnsafeMutableBytes(of: &value) { rawBytes in
      guard let baseAddress = rawBytes.baseAddress else { return }
      SecureWipe.erase(baseAddress, byteCount: rawBytes.count)
    }
  }

}

private struct Poly1305Storage {
  var r0: UInt64
  var r1: UInt64
  var r2: UInt64
  var scaledR1: UInt64
  var scaledR2: UInt64
  var h0: UInt64 = 0
  var h1: UInt64 = 0
  var h2: UInt64 = 0
  var pad0: UInt64
  var pad1: UInt64
  var buffer = SIMD16<UInt8>(repeating: 0)
  var bufferCount = 0
}

/// Stable owner for Poly1305 state. The single allocation gives the hot path
/// direct storage access without per-property dynamic exclusivity checks. This
/// owner never crosses a concurrency boundary.
private final class Poly1305 {
  private let storage: UnsafeMutablePointer<Poly1305Storage>

  init(key: Span<UInt8>) {
    // The clamped 128-bit multiplier is represented as 44/44/42-bit limbs.
    let low = ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 0)
    let high = ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 8)
    let r0 = low & 0x0ffc_0fff_ffff
    let r1 = ((low >> 44) | (high << 20)) & 0x0fff_ffc0_ffff
    let r2 = (high >> 24) & 0x00ff_ffff_c0f
    storage = .allocate(capacity: 1)
    storage.initialize(
      to: Poly1305Storage(
        r0: r0,
        r1: r1,
        r2: r2,
        scaledR1: r1 * 20,
        scaledR2: r2 * 20,
        pad0: ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 16),
        pad1: ChaCha20Poly1305.readUInt64LittleEndian(key, offset: 24)
      )
    )
  }

  deinit {
    // Unsafe boundary invariants:
    // - `storage` is the sole owner of one initialized value.
    // - No pointer derived from it escapes a synchronous method call.
    // - The complete initialized allocation is wiped before exactly-once
    //   deinitialization and deallocation.
    SecureWipe.erase(
      UnsafeMutableRawPointer(storage),
      byteCount: MemoryLayout<Poly1305Storage>.stride
    )
    storage.deinitialize(count: 1)
    storage.deallocate()
  }

  func update(_ bytes: Span<UInt8>) {
    let storage = storage
    var offset = 0
    if storage.pointee.bufferCount > 0 {
      let count = min(16 - storage.pointee.bufferCount, bytes.count)
      var index = 0
      while index < count {
        storage.pointee.buffer[storage.pointee.bufferCount + index] = bytes[offset + index]
        index += 1
      }
      storage.pointee.bufferCount += count
      offset += count
      if storage.pointee.bufferCount == 16 {
        processFullBlock()
        storage.pointee.bufferCount = 0
      }
    }
    if offset + 16 <= bytes.count {
      bytes.withUnsafeBytes { rawBytes in
        // Unsafe boundary invariants:
        // - Every load is an unaligned read of 16 initialized bytes inside the
        //   validated span range.
        // - The source pointer is borrowed only by this synchronous closure.
        // - Poly1305 storage is disjoint from the immutable source bytes.
        let baseAddress = rawBytes.baseAddress.unsafelyUnwrapped
        while offset + 16 <= bytes.count {
          let block = baseAddress.advanced(by: offset)
          let low = UInt64(littleEndian: block.loadUnaligned(as: UInt64.self))
          let high = UInt64(
            littleEndian: block.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
          )
          processBlock(low: low, high: high, highBit: 1 << 40)
          offset += 16
        }
      }
    }
    while offset < bytes.count {
      storage.pointee.buffer[storage.pointee.bufferCount] = bytes[offset]
      storage.pointee.bufferCount += 1
      offset += 1
    }
  }

  func padToBlock() {
    let storage = storage
    guard storage.pointee.bufferCount > 0 else { return }
    while storage.pointee.bufferCount < 16 {
      storage.pointee.buffer[storage.pointee.bufferCount] = 0
      storage.pointee.bufferCount += 1
    }
    processFullBlock()
    storage.pointee.bufferCount = 0
  }

  func finalize() -> [UInt8] {
    let storage = storage
    if storage.pointee.bufferCount > 0 {
      var index = storage.pointee.bufferCount
      storage.pointee.buffer[index] = 1
      index += 1
      while index < 16 {
        storage.pointee.buffer[index] = 0
        index += 1
      }
      processPartialBlock()
      storage.pointee.bufferCount = 0
    }

    let mask44: UInt64 = (1 << 44) - 1
    let mask42: UInt64 = (1 << 42) - 1
    var h0 = storage.pointee.h0
    var h1 = storage.pointee.h1
    var h2 = storage.pointee.h2
    var carry = h1 >> 44
    h1 &= mask44
    h2 &+= carry
    carry = h2 >> 42
    h2 &= mask42
    h0 &+= carry * 5
    carry = h0 >> 44
    h0 &= mask44
    h1 &+= carry

    var g0 = h0 + 5
    carry = g0 >> 44
    g0 &= mask44
    var g1 = h1 + carry
    carry = g1 >> 44
    g1 &= mask44
    let g2 = (h2 + carry) &- (1 << 42)
    let mask = (g2 >> 63) &- 1
    let inverseMask = ~mask
    h0 = (h0 & inverseMask) | (g0 & mask)
    h1 = (h1 & inverseMask) | (g1 & mask)
    h2 = (h2 & inverseMask) | (g2 & mask)

    let word0 = h0 | (h1 << 44)
    let word1 = (h1 >> 20) | (h2 << 24)
    let (low, overflow) = word0.addingReportingOverflow(storage.pointee.pad0)
    var high = word1 &+ storage.pointee.pad1
    if overflow { high &+= 1 }
    var result = [UInt8](repeating: 0, count: 16)
    ChaCha20Poly1305.writeUInt64LittleEndian(low, into: &result, offset: 0)
    ChaCha20Poly1305.writeUInt64LittleEndian(high, into: &result, offset: 8)
    return result
  }

  private func processFullBlock() {
    var buffer = storage.pointee.buffer
    withUnsafeBytes(of: &buffer) { rawBytes in
      let baseAddress = rawBytes.baseAddress.unsafelyUnwrapped
      processBlock(
        low: UInt64(littleEndian: baseAddress.loadUnaligned(as: UInt64.self)),
        high: UInt64(
          littleEndian: baseAddress.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
        ),
        highBit: 1 << 40
      )
    }
    wipe(&buffer)
  }


  private func processPartialBlock() {
    var buffer = storage.pointee.buffer
    withUnsafeBytes(of: &buffer) { rawBytes in
      let baseAddress = rawBytes.baseAddress.unsafelyUnwrapped
      processBlock(
        low: UInt64(littleEndian: baseAddress.loadUnaligned(as: UInt64.self)),
        high: UInt64(
          littleEndian: baseAddress.loadUnaligned(fromByteOffset: 8, as: UInt64.self)
        ),
        highBit: 0
      )
    }
    wipe(&buffer)
  }

  @inline(__always)
  private func processBlock(low: UInt64, high: UInt64, highBit: UInt64) {
    // The accumulator remains below 2^44/2^44/2^42 after every reduction.
    // Each UInt128 product is therefore below 2^91, including all three-term
    // sums, so wrapping operators cannot actually wrap. Local accumulation
    // avoids dynamic exclusivity checks on each storage field.
    let mask44: UInt64 = (1 << 44) - 1
    let mask42: UInt64 = (1 << 42) - 1
    let state = storage
    let h0 = state.pointee.h0 &+ (low & mask44)
    let h1 = state.pointee.h1 &+ (((low >> 44) | (high << 20)) & mask44)
    let h2 = state.pointee.h2 &+ (((high >> 24) & mask42) | highBit)
    let r0 = state.pointee.r0
    let r1 = state.pointee.r1
    let r2 = state.pointee.r2
    let scaledR1 = state.pointee.scaledR1
    let scaledR2 = state.pointee.scaledR2

    var product0 = UInt128(h0) &* UInt128(r0)
    product0 &+= UInt128(h1) &* UInt128(scaledR2)
    product0 &+= UInt128(h2) &* UInt128(scaledR1)
    var product1 = UInt128(h0) &* UInt128(r1)
    product1 &+= UInt128(h1) &* UInt128(r0)
    product1 &+= UInt128(h2) &* UInt128(scaledR2)
    var product2 = UInt128(h0) &* UInt128(r2)
    product2 &+= UInt128(h1) &* UInt128(r1)
    product2 &+= UInt128(h2) &* UInt128(r0)

    var carry = UInt64(truncatingIfNeeded: product0 >> 44)
    var reducedH0 = UInt64(truncatingIfNeeded: product0) & mask44
    product1 &+= UInt128(carry)
    carry = UInt64(truncatingIfNeeded: product1 >> 44)
    var reducedH1 = UInt64(truncatingIfNeeded: product1) & mask44
    product2 &+= UInt128(carry)
    carry = UInt64(truncatingIfNeeded: product2 >> 42)
    let reducedH2 = UInt64(truncatingIfNeeded: product2) & mask42
    reducedH0 &+= carry * 5
    carry = reducedH0 >> 44
    reducedH0 &= mask44
    reducedH1 &+= carry
    state.pointee.h0 = reducedH0
    state.pointee.h1 = reducedH1
    state.pointee.h2 = reducedH2
  }


  private func wipe<T>(_ value: inout T) {
    withUnsafeMutableBytes(of: &value) { rawBytes in
      guard let baseAddress = rawBytes.baseAddress else { return }
      SecureWipe.erase(baseAddress, byteCount: rawBytes.count)
    }
  }
}
