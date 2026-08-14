import SSLCore

public struct SHA256Context: ~Copyable, HashContext, Sendable {
  public static let digestByteCount = 32

  private static let blockByteCount = 64
  package static let maximumInputByteCount = UInt64.max >> 3
  @inline(__always)
  package static var initialState: SIMD8<UInt32> {
    SIMD8(
      0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
      0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19
    )
  }

  private var state: SIMD8<UInt32>
  private var pendingBytes: SIMD64<UInt8>
  private var pendingByteCount: Int
  private var totalByteCount: UInt64

  public init() {
    state = Self.initialState
    pendingBytes = SIMD64<UInt8>(repeating: 0)
    pendingByteCount = 0
    totalByteCount = 0
  }

  @inline(__always)
  @usableFromInline
  package static func hashOneShot(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    let inputByteCount = UInt64(input.count)
    try validateAdditionalInputByteCount(inputByteCount, currentByteCount: 0)
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(
        expected: Self.digestByteCount,
        actual: output.count
      )
    }

    let completeBlockCount = input.count / blockByteCount
    let remainingByteCount = input.count - completeBlockCount * blockByteCount
    let bitCount = inputByteCount << 3

    #if os(macOS) && arch(arm64) && canImport(simd) && !SWIFT_SSL_TSAN
      if completeBlockCount > 0, remainingByteCount == 0 {
        var state = Self.initialState
        // Unsafe invariants: the nonempty span retains completeBlockCount
        // initialized 64-byte blocks for this synchronous borrow. The kernel
        // performs unaligned read-only loads, and no pointer escapes or crosses
        // a Sendable boundary.
        input.bytes.withUnsafeBytes { bytes in
          SHA256ARM64Kernel.compressBlocksAndAlignedPadding(
            state: &state,
            blocks: bytes.baseAddress.unsafelyUnwrapped,
            blockCount: completeBlockCount,
            bitCount: bitCount
          )
        }
        writeOneShotDigest(state, into: &output)
        return
      }
    #endif

    hashOneShotGeneral(
      input,
      completeBlockCount: completeBlockCount,
      remainingByteCount: remainingByteCount,
      bitCount: bitCount,
      into: &output
    )
  }

  @inline(never)
  private static func hashOneShotGeneral(
    _ input: Span<UInt8>,
    completeBlockCount: Int,
    remainingByteCount: Int,
    bitCount: UInt64,
    into output: inout MutableSpan<UInt8>
  ) {
    var state = Self.initialState

    if completeBlockCount > 0 {
      SHA256Compression.compressInputBlocks(
        state: &state,
        input: input,
        at: 0,
        blockCount: completeBlockCount
      )
    }

    if remainingByteCount == 0 {
      SHA256Compression.compressPaddingBlock(
        state: &state,
        bitCount: bitCount
      )
    } else {
      var padding = SIMD64<UInt8>(repeating: 0)
      copyOneShotRemainder(
        input,
        at: completeBlockCount * blockByteCount,
        byteCount: remainingByteCount,
        into: &padding
      )
      padding[remainingByteCount] = 0x80
      if remainingByteCount > 55 {
        SHA256Compression.compressPendingBlock(
          state: &state,
          pendingBytes: padding
        )
        padding = SIMD64<UInt8>(repeating: 0)
      }
      writeOneShotBitCount(bitCount, into: &padding)
      SHA256Compression.compressPendingBlock(
        state: &state,
        pendingBytes: padding
      )
    }
    writeOneShotDigest(state, into: &output)
  }

  @inline(__always)
  private static func copyOneShotRemainder(
    _ input: Span<UInt8>,
    at offset: Int,
    byteCount: Int,
    into padding: inout SIMD64<UInt8>
  ) {
    // Unsafe invariants: input retains at least offset + byteCount initialized
    // bytes and padding exclusively owns 64 initialized bytes. The one-shot
    // caller proves byteCount is 1...63 and both ranges are disjoint and in
    // bounds. Raw byte access preserves binding, and no pointer escapes.
    input.bytes.withUnsafeBytes { sourceBytes in
      withUnsafeMutableBytes(of: &padding) { destinationBytes in
        destinationBytes.baseAddress.unsafelyUnwrapped.copyMemory(
          from: sourceBytes.baseAddress.unsafelyUnwrapped.advanced(by: offset),
          byteCount: byteCount
        )
      }
    }
  }

  @inline(__always)
  private static func writeOneShotBitCount(
    _ bitCount: UInt64,
    into padding: inout SIMD64<UInt8>
  ) {
    var index = 0
    while index < 8 {
      padding[56 + index] = UInt8(
        truncatingIfNeeded: bitCount >> UInt64((7 - index) * 8)
      )
      index += 1
    }
  }

  @inline(__always)
  private static func writeOneShotDigest(
    _ state: SIMD8<UInt32>,
    into output: inout MutableSpan<UInt8>
  ) {
    var index = 0
    while index < 8 {
      let word = state[index]
      let outputOffset = index * 4
      output[outputOffset] = UInt8(truncatingIfNeeded: word >> 24)
      output[outputOffset + 1] = UInt8(truncatingIfNeeded: word >> 16)
      output[outputOffset + 2] = UInt8(truncatingIfNeeded: word >> 8)
      output[outputOffset + 3] = UInt8(truncatingIfNeeded: word)
      index += 1
    }
  }

  private init(
    state: SIMD8<UInt32>,
    pendingBytes: SIMD64<UInt8>,
    pendingByteCount: Int,
    totalByteCount: UInt64
  ) {
    self.state = state
    self.pendingBytes = pendingBytes
    self.pendingByteCount = pendingByteCount
    self.totalByteCount = totalByteCount
  }

  public mutating func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError) {
    let inputByteCount = UInt64(input.count)
    try Self.validateAdditionalInputByteCount(
      inputByteCount,
      currentByteCount: totalByteCount
    )

    totalByteCount += inputByteCount
    var inputOffset = 0

    if pendingByteCount > 0 {
      let requiredByteCount = Self.blockByteCount - pendingByteCount
      let copiedByteCount = Swift.min(requiredByteCount, input.count)
      copyInput(
        input,
        inputOffset: inputOffset,
        copiedByteCount: copiedByteCount,
        pendingOffset: pendingByteCount
      )
      pendingByteCount += copiedByteCount
      inputOffset += copiedByteCount

      if pendingByteCount == Self.blockByteCount {
        compressPendingBlock()
        pendingByteCount = 0
      }
    }

    let completeBlockCount =
      (input.count - inputOffset) / Self.blockByteCount
    if completeBlockCount > 0 {
      compressInputBlocks(
        input,
        at: inputOffset,
        blockCount: completeBlockCount
      )
      inputOffset += completeBlockCount * Self.blockByteCount
    }

    let remainingByteCount = input.count - inputOffset
    if remainingByteCount > 0 {
      copyInput(
        input,
        inputOffset: inputOffset,
        copiedByteCount: remainingByteCount,
        pendingOffset: 0
      )
      pendingByteCount = remainingByteCount
    }
  }

  @inline(__always)
  static func validateAdditionalInputByteCount(
    _ inputByteCount: UInt64,
    currentByteCount: UInt64
  ) throws(CryptoInputError) {
    guard
      currentByteCount <= Self.maximumInputByteCount,
      inputByteCount <= Self.maximumInputByteCount - currentByteCount
    else {
      throw .inputTooLong(limit: Self.maximumInputByteCount)
    }
  }

  public borrowing func clone() -> SHA256Context {
    SHA256Context(
      state: state,
      pendingBytes: pendingBytes,
      pendingByteCount: pendingByteCount,
      totalByteCount: totalByteCount
    )
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try finalizeInPlace(into: &output)
  }

  @usableFromInline
  mutating func finalizeInPlace(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(
        expected: Self.digestByteCount,
        actual: output.count
      )
    }

    let bitCount = totalByteCount << 3
    if pendingByteCount == 0 {
      SHA256Compression.compressPaddingBlock(
        state: &state,
        bitCount: bitCount
      )
    } else {
      pendingBytes[pendingByteCount] = 0x80
      pendingByteCount += 1

      if pendingByteCount > 56 {
        zeroPendingBytes(from: pendingByteCount, to: Self.blockByteCount)
        compressPendingBlock()
        pendingByteCount = 0
      }

      zeroPendingBytes(from: pendingByteCount, to: 56)
      var lengthByteIndex = 0
      while lengthByteIndex < 8 {
        let shift = UInt64((7 - lengthByteIndex) * 8)
        pendingBytes[56 + lengthByteIndex] = UInt8(
          truncatingIfNeeded: bitCount >> shift
        )
        lengthByteIndex += 1
      }
      compressPendingBlock()
    }

    var index = 0
    while index < 8 {
      let word = state[index]
      let outputOffset = index * 4
      output[outputOffset] = UInt8(truncatingIfNeeded: word >> 24)
      output[outputOffset + 1] = UInt8(truncatingIfNeeded: word >> 16)
      output[outputOffset + 2] = UInt8(truncatingIfNeeded: word >> 8)
      output[outputOffset + 3] = UInt8(truncatingIfNeeded: word)
      index += 1
    }
  }

  @inline(__always)
  private mutating func copyInput(
    _ input: Span<UInt8>,
    inputOffset: Int,
    copiedByteCount: Int,
    pendingOffset: Int
  ) {
    guard copiedByteCount > 0 else {
      return
    }

    // Unsafe invariants: `pendingBytes` owns 64 initialized bytes for the
    // entire synchronous closure. The caller derives both offsets and the
    // byte count from validated span and block bounds, so the additions are
    // representable and both ranges are in bounds. Source and destination
    // do not overlap. Raw byte access neither binds nor rebinds memory.
    // Neither pointer escapes nor crosses a Sendable boundary.
    input.bytes.withUnsafeBytes { sourceBytes in
      withUnsafeMutableBytes(of: &pendingBytes) { destinationBytes in
        let source = sourceBytes.baseAddress.unsafelyUnwrapped
          .advanced(by: inputOffset)
        let destination = destinationBytes.baseAddress.unsafelyUnwrapped
          .advanced(by: pendingOffset)
        destination.copyMemory(
          from: source,
          byteCount: copiedByteCount
        )
      }
    }
  }

  @inline(__always)
  private mutating func zeroPendingBytes(from start: Int, to end: Int) {
    guard start < end else {
      return
    }

    // Unsafe invariants: `pendingBytes` owns 64 initialized bytes for the
    // entire synchronous closure. Finalization supplies a representable
    // half-open subrange within those bytes. Raw byte stores preserve the
    // existing binding and initialization state. The pointer does not
    // escape or cross a Sendable boundary, and byte access needs alignment 1.
    withUnsafeMutableBytes(of: &pendingBytes) { bytes in
      var index = start
      while index < end {
        bytes[index] = 0
        index += 1
      }
    }
  }

  @inline(__always)
  private mutating func compressInputBlocks(
    _ input: Span<UInt8>,
    at offset: Int,
    blockCount: Int
  ) {
    SHA256Compression.compressInputBlocks(
      state: &state,
      input: input,
      at: offset,
      blockCount: blockCount
    )
  }

  @inline(__always)
  private mutating func compressPendingBlock() {
    SHA256Compression.compressPendingBlock(
      state: &state,
      pendingBytes: pendingBytes
    )
  }

  package mutating func eraseSensitiveState() {
    // Unsafe boundary invariants:
    // - state and pendingBytes are fully initialized inline values owned
    //   exclusively by this context for both synchronous closures.
    // - Raw byte access does not bind or rebind storage, and no pointer escapes.
    // - The method is used when SHA-256 state contains key-derived HMAC state;
    //   volatile stores complete before the owner is destroyed.
    // - No Sendable boundary is crossed while either value is being erased.
    withUnsafeMutableBytes(of: &state) { bytes in
      SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
    }
    withUnsafeMutableBytes(of: &pendingBytes) { bytes in
      SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
    }
    pendingByteCount = 0
    totalByteCount = 0
  }
}
