import SSLCore

#if os(macOS) && arch(arm64) && canImport(simd)
  package enum SHA256Pair {
    package static func hash(
      _ firstInput: Span<UInt8>,
      _ secondInput: Span<UInt8>,
      into output: inout MutableSpan<UInt8>
    ) throws(CryptoInputError) {
      guard firstInput.count == secondInput.count else {
        throw .invalidLength(
          expected: firstInput.count,
          actual: secondInput.count
        )
      }
      let expectedOutputByteCount = SHA256Context.digestByteCount * 2
      guard output.count == expectedOutputByteCount else {
        throw .invalidOutputLength(
          expected: expectedOutputByteCount,
          actual: output.count
        )
      }
      guard UInt64(firstInput.count) <= SHA256Context.maximumInputByteCount else {
        throw .inputTooLong(limit: SHA256Context.maximumInputByteCount)
      }

      var firstState = SHA256Context.initialState
      var secondState = SHA256Context.initialState
      let completeBlockCount = firstInput.count / 64

      if completeBlockCount > 0 {
        // Unsafe invariants: both spans retain their owners for the complete
        // nested synchronous borrow. The validated equal lengths contain
        // completeBlockCount initialized 64-byte blocks. The kernel performs
        // only unaligned read-only byte loads and neither pointer escapes.
        firstInput.bytes.withUnsafeBytes { firstBytes in
          secondInput.bytes.withUnsafeBytes { secondBytes in
            SHA256ARM64Kernel.compressBlockPairs(
              firstState: &firstState,
              secondState: &secondState,
              firstBlocks: firstBytes.baseAddress.unsafelyUnwrapped,
              secondBlocks: secondBytes.baseAddress.unsafelyUnwrapped,
              blockCount: completeBlockCount
            )
          }
        }
      }

      let remainingOffset = completeBlockCount * 64
      var firstPadding = SIMD64<UInt8>(repeating: 0)
      var secondPadding = SIMD64<UInt8>(repeating: 0)
      let remainingByteCount = firstInput.count - remainingOffset
      if remainingByteCount > 0 {
        copyRemainder(
          firstInput,
          at: remainingOffset,
          byteCount: remainingByteCount,
          into: &firstPadding
        )
        copyRemainder(
          secondInput,
          at: remainingOffset,
          byteCount: remainingByteCount,
          into: &secondPadding
        )
      }

      firstPadding[remainingByteCount] = 0x80
      secondPadding[remainingByteCount] = 0x80
      if remainingByteCount > 55 {
        compressPaddingPair(
          firstState: &firstState,
          secondState: &secondState,
          firstPadding: firstPadding,
          secondPadding: secondPadding
        )
        firstPadding = SIMD64<UInt8>(repeating: 0)
        secondPadding = SIMD64<UInt8>(repeating: 0)
      }

      let bitCount = UInt64(firstInput.count) << 3
      writeBigEndian(bitCount, into: &firstPadding, at: 56)
      writeBigEndian(bitCount, into: &secondPadding, at: 56)
      compressPaddingPair(
        firstState: &firstState,
        secondState: &secondState,
        firstPadding: firstPadding,
        secondPadding: secondPadding
      )
      writeDigest(firstState, into: &output, at: 0)
      writeDigest(secondState, into: &output, at: SHA256Context.digestByteCount)
    }

    @inline(__always)
    private static func copyRemainder(
      _ input: Span<UInt8>,
      at offset: Int,
      byteCount: Int,
      into padding: inout SIMD64<UInt8>
    ) {
      // Unsafe invariants: input retains at least offset + byteCount
      // initialized bytes and padding exclusively owns 64 initialized bytes.
      // byteCount is at most 63, both ranges are in bounds and disjoint, raw
      // byte access preserves binding, and neither pointer escapes.
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
    private static func compressPaddingPair(
      firstState: inout SIMD8<UInt32>,
      secondState: inout SIMD8<UInt32>,
      firstPadding: borrowing SIMD64<UInt8>,
      secondPadding: borrowing SIMD64<UInt8>
    ) {
      SHA256ARM64Kernel.compressPair(
        firstState: &firstState,
        secondState: &secondState,
        firstBlock: firstPadding,
        secondBlock: secondPadding
      )
    }

    @inline(__always)
    private static func writeBigEndian(
      _ value: UInt64,
      into bytes: inout SIMD64<UInt8>,
      at offset: Int
    ) {
      var index = 0
      while index < 8 {
        bytes[offset + index] = UInt8(
          truncatingIfNeeded: value >> UInt64((7 - index) * 8)
        )
        index += 1
      }
    }

    @inline(__always)
    private static func writeDigest(
      _ state: SIMD8<UInt32>,
      into output: inout MutableSpan<UInt8>,
      at digestOffset: Int
    ) {
      var index = 0
      while index < 8 {
        let word = state[index]
        let outputOffset = digestOffset + index * 4
        output[outputOffset] = UInt8(truncatingIfNeeded: word >> 24)
        output[outputOffset + 1] = UInt8(truncatingIfNeeded: word >> 16)
        output[outputOffset + 2] = UInt8(truncatingIfNeeded: word >> 8)
        output[outputOffset + 3] = UInt8(truncatingIfNeeded: word)
        index += 1
      }
    }
  }
#endif
