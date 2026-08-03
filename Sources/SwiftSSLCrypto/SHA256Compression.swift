enum SHA256Compression {
  @inline(__always)
  static func compressInputBlocks(
    state: inout SIMD8<UInt32>,
    input: Span<UInt8>,
    at offset: Int,
    blockCount: Int
  ) {
    #if os(macOS) && arch(arm64) && canImport(simd)
      // Unsafe invariants: the caller has established `offset >= 0`,
      // `blockCount > 0`, and `blockCount * 64` bytes in `input`; therefore
      // every block offset is representable and in range. The span's owner
      // remains alive for this synchronous closure. The kernel performs
      // unaligned read-only byte loads, does not bind or mutate input memory,
      // and the derived address does not escape or cross a Sendable boundary.
      input.bytes.withUnsafeBytes { bytes in
        SHA256ARM64Kernel.compressBlocks(
          state: &state,
          blocks: bytes.baseAddress.unsafelyUnwrapped.advanced(by: offset),
          blockCount: blockCount
        )
      }
    #else
      // Unsafe invariants: the caller proves `offset >= 0`, `blockCount > 0`,
      // and that the span contains `blockCount * 64` initialized bytes from
      // `offset`. The span owner remains alive for the synchronous borrow.
      // Each derived pointer is used only for unaligned read-only word loads;
      // it does not escape, bind memory, mutate input, or cross Sendable.
      input.bytes.withUnsafeBytes { bytes in
        let firstBlock = bytes.baseAddress.unsafelyUnwrapped.advanced(by: offset)
        var blockIndex = 0
        while blockIndex < blockCount {
          let block = firstBlock.advanced(by: blockIndex * 64)
          SHA256ScalarKernel.compress(
            state: &state,
            initialSchedule: loadInitialSchedule(from: block)
          )
          blockIndex += 1
        }
      }
    #endif
  }

  @inline(__always)
  static func compressPendingBlock(
    state: inout SIMD8<UInt32>,
    pendingBytes: borrowing SIMD64<UInt8>
  ) {
    #if os(macOS) && arch(arm64) && canImport(simd)
      withUnsafeBytes(of: pendingBytes) { bytes in
        SHA256ARM64Kernel.compressBlocks(
          state: &state,
          blocks: bytes.baseAddress.unsafelyUnwrapped,
          blockCount: 1
        )
      }
    #else
      // Unsafe invariants: `pendingBytes` is a fully initialized inline
      // 64-byte value retained for this synchronous closure. The helper makes
      // unaligned read-only loads, and no pointer escapes or crosses Sendable.
      withUnsafeBytes(of: pendingBytes) { bytes in
        SHA256ScalarKernel.compress(
          state: &state,
          initialSchedule: loadInitialSchedule(
            from: bytes.baseAddress.unsafelyUnwrapped
          )
        )
      }
    #endif
  }

  @inline(__always)
  static func compressPaddingBlock(
    state: inout SIMD8<UInt32>,
    bitCount: UInt64
  ) {
    var initialSchedule = SIMD16<UInt32>(repeating: 0)
    initialSchedule[0] = 0x8000_0000
    initialSchedule[14] = UInt32(truncatingIfNeeded: bitCount >> 32)
    initialSchedule[15] = UInt32(truncatingIfNeeded: bitCount)

    #if os(macOS) && arch(arm64) && canImport(simd)
      SHA256ARM64Kernel.compress(
        state: &state,
        initialSchedule: initialSchedule
      )
    #else
      SHA256ScalarKernel.compress(
        state: &state,
        initialSchedule: initialSchedule
      )
    #endif
  }

  @inline(__always)
  static func compressUsingScalar(
    state: inout SIMD8<UInt32>,
    initialSchedule: SIMD16<UInt32>
  ) {
    SHA256ScalarKernel.compress(
      state: &state,
      initialSchedule: initialSchedule
    )
  }

  #if os(macOS) && arch(arm64) && canImport(simd)
    @inline(__always)
    static func compressUsingARM64SHA2(
      state: inout SIMD8<UInt32>,
      initialSchedule: SIMD16<UInt32>
    ) {
      SHA256ARM64Kernel.compress(
        state: &state,
        initialSchedule: initialSchedule
      )
    }
  #endif

  @inline(__always)
  private static func loadInitialSchedule(
    from block: UnsafeRawPointer
  ) -> SIMD16<UInt32> {
    var initialSchedule = SIMD16<UInt32>(repeating: 0)
    var wordIndex = 0
    while wordIndex < 16 {
      initialSchedule[wordIndex] = block.loadUnaligned(
        fromByteOffset: wordIndex * MemoryLayout<UInt32>.stride,
        as: UInt32.self
      ).bigEndian
      wordIndex += 1
    }
    return initialSchedule
  }
}
