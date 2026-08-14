#if os(macOS) && arch(arm64) && canImport(simd) && !SWIFT_SSL_TSAN
  import _Volatile
  import simd

  @_silgen_name("llvm.aarch64.neon.ld1x4.v4i32.p0")
  private func loadFourSHA256Vectors(
    _ pointer: UnsafeRawPointer
  ) -> (
    SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>
  )

  enum SHA256ARM64Kernel {
    private static let roundConstants: [UInt32] = [
      0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5,
      0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
      0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3,
      0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
      0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC,
      0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
      0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7,
      0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
      0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13,
      0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
      0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3,
      0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
      0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5,
      0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
      0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208,
      0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
    ]

    @inline(__always)
    static func compressBlocks(
      state: inout SIMD8<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int
    ) {
      guard blockCount > 0 else {
        return
      }

      var state0 = SIMD4<UInt32>(
        state[0], state[1], state[2], state[3]
      )
      var state1 = SIMD4<UInt32>(
        state[4], state[5], state[6], state[7]
      )

      Self.roundConstants.withUnsafeBufferPointer { constantWords in
        let constantTable = UnsafeRawPointer(
          constantWords.baseAddress.unsafelyUnwrapped
        )
        if blockCount == 1 {
          let messages = loadMessages(from: blocks)
          let compressed = compressBlock(
            state0: state0,
            state1: state1,
            message0: messages.0,
            message1: messages.1,
            message2: messages.2,
            message3: messages.3,
            constantTable: constantTable
          )
          state0 = vaddq_u32(compressed.0, state0)
          state1 = vaddq_u32(compressed.1, state1)
          return
        }

        var constantTableAddress = UInt64(UInt(bitPattern: constantTable))
        withUnsafePointer(to: &constantTableAddress) { addressPointer in
          let addressRegister = VolatileMappedRegister<UInt64>(
            unsafeBitPattern: UInt(bitPattern: addressPointer)
          )
          (state0, state1) = compressMultipleBlocks(
            state0: state0,
            state1: state1,
            blocks: blocks,
            blockCount: blockCount,
            constantTableAddress: addressRegister
          )
        }
      }

      storeState(state0, state1, into: &state)
    }

    @inline(__always)
    static func compressBlocksAndAlignedPadding(
      state: inout SIMD8<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int,
      bitCount: UInt64
    ) {
      precondition(blockCount > 0)
      let state0 = SIMD4<UInt32>(
        state[0], state[1], state[2], state[3]
      )
      let state1 = SIMD4<UInt32>(
        state[4], state[5], state[6], state[7]
      )

      Self.roundConstants.withUnsafeBufferPointer { constantWords in
        let compressed = compressMultipleBlocksAndAlignedPadding(
          state0: state0,
          state1: state1,
          blocks: blocks,
          blockCount: blockCount,
          bitCount: bitCount,
          constantTable: UnsafeRawPointer(
            constantWords.baseAddress.unsafelyUnwrapped
          )
        )
        storeState(compressed.0, compressed.1, into: &state)
      }
    }

    @inline(__always)
    static func compress(
      state: inout SIMD8<UInt32>,
      initialSchedule: SIMD16<UInt32>
    ) {
      var state0 = SIMD4<UInt32>(
        state[0], state[1], state[2], state[3]
      )
      var state1 = SIMD4<UInt32>(
        state[4], state[5], state[6], state[7]
      )

      Self.roundConstants.withUnsafeBufferPointer { constantWords in
        let compressed = compressBlock(
          state0: state0,
          state1: state1,
          message0: SIMD4(
            initialSchedule[0], initialSchedule[1],
            initialSchedule[2], initialSchedule[3]
          ),
          message1: SIMD4(
            initialSchedule[4], initialSchedule[5],
            initialSchedule[6], initialSchedule[7]
          ),
          message2: SIMD4(
            initialSchedule[8], initialSchedule[9],
            initialSchedule[10], initialSchedule[11]
          ),
          message3: SIMD4(
            initialSchedule[12], initialSchedule[13],
            initialSchedule[14], initialSchedule[15]
          ),
          constantTable: UnsafeRawPointer(
            constantWords.baseAddress.unsafelyUnwrapped
          )
        )
        state0 = vaddq_u32(compressed.0, state0)
        state1 = vaddq_u32(compressed.1, state1)
      }
      storeState(state0, state1, into: &state)
    }

    @inline(__always)
    static func compressBlockPairs(
      firstState: inout SIMD8<UInt32>,
      secondState: inout SIMD8<UInt32>,
      firstBlocks: UnsafeRawPointer,
      secondBlocks: UnsafeRawPointer,
      blockCount: Int
    ) {
      guard blockCount > 0 else {
        return
      }

      let firstState0 = SIMD4<UInt32>(
        firstState[0], firstState[1], firstState[2], firstState[3]
      )
      let firstState1 = SIMD4<UInt32>(
        firstState[4], firstState[5], firstState[6], firstState[7]
      )
      let secondState0 = SIMD4<UInt32>(
        secondState[0], secondState[1], secondState[2], secondState[3]
      )
      let secondState1 = SIMD4<UInt32>(
        secondState[4], secondState[5], secondState[6], secondState[7]
      )

      Self.roundConstants.withUnsafeBufferPointer { constantWords in
        var constantTableAddress = UInt64(
          UInt(bitPattern: constantWords.baseAddress.unsafelyUnwrapped)
        )
        withUnsafePointer(to: &constantTableAddress) { addressPointer in
          let addressRegister = VolatileMappedRegister<UInt64>(
            unsafeBitPattern: UInt(bitPattern: addressPointer)
          )
          let compressed = compressMultipleBlockPairs(
            firstState0: firstState0,
            firstState1: firstState1,
            secondState0: secondState0,
            secondState1: secondState1,
            firstBlocks: firstBlocks,
            secondBlocks: secondBlocks,
            blockCount: blockCount,
            constantTableAddress: addressRegister
          )
          storeState(compressed.0, compressed.1, into: &firstState)
          storeState(compressed.2, compressed.3, into: &secondState)
        }
      }
    }

    @inline(__always)
    static func compressPair(
      firstState: inout SIMD8<UInt32>,
      secondState: inout SIMD8<UInt32>,
      firstBlock: SIMD64<UInt8>,
      secondBlock: SIMD64<UInt8>
    ) {
      withUnsafeBytes(of: firstBlock) { firstBytes in
        withUnsafeBytes(of: secondBlock) { secondBytes in
          compressBlockPairs(
            firstState: &firstState,
            secondState: &secondState,
            firstBlocks: firstBytes.baseAddress.unsafelyUnwrapped,
            secondBlocks: secondBytes.baseAddress.unsafelyUnwrapped,
            blockCount: 1
          )
        }
      }
    }

    @inline(never)
    private static func compressMultipleBlocks(
      state0 initialState0: SIMD4<UInt32>,
      state1 initialState1: SIMD4<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int,
      constantTableAddress: VolatileMappedRegister<UInt64>
    ) -> (SIMD4<UInt32>, SIMD4<UInt32>) {
      var state0 = initialState0
      var state1 = initialState1
      var block = blocks
      var remainingBlockCount = blockCount

      // Unsafe invariants: the synchronous caller retains the memory owner
      // and supplies at least two complete initialized 64-byte blocks.
      // Advancing exactly once per remaining block keeps every read in that
      // validated range and cannot overflow independently of the range.
      // Reads are unaligned and byte-preserving; memory is never rebound or
      // mutated. The caller also owns one initialized UInt64 containing the
      // constant table's nonzero address for the complete synchronous borrow.
      // Its volatile load recreates that same pointer inside every iteration,
      // keeping constant loads in this loop without changing their validated
      // 256-byte range. No pointer escapes or crosses a Sendable boundary.
      repeat {
        let savedState0 = state0
        let savedState1 = state1
        let blockConstantTable = UnsafeRawPointer(
          bitPattern: UInt(constantTableAddress.load())
        ).unsafelyUnwrapped
        let messages = loadMessages(from: block)
        let compressed = compressBlock(
          state0: state0,
          state1: state1,
          message0: messages.0,
          message1: messages.1,
          message2: messages.2,
          message3: messages.3,
          constantTable: blockConstantTable
        )
        state0 = vaddq_u32(compressed.0, savedState0)
        state1 = vaddq_u32(compressed.1, savedState1)
        block = block.advanced(by: 64)
        // The outer guard establishes a positive count and each iteration
        // executes exactly once per remaining block, so subtraction cannot
        // underflow before the loop reaches zero.
        remainingBlockCount &-= 1
      } while remainingBlockCount != 0
      return (state0, state1)
    }

    @inline(never)
    private static func compressMultipleBlocksAndAlignedPadding(
      state0 initialState0: SIMD4<UInt32>,
      state1 initialState1: SIMD4<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int,
      bitCount: UInt64,
      constantTable: UnsafeRawPointer
    ) -> (SIMD4<UInt32>, SIMD4<UInt32>) {
      var state0 = initialState0
      var state1 = initialState1
      var block = blocks
      var remainingBlockCount = blockCount

      // Unsafe invariants: the synchronous caller retains the input owner and
      // supplies blockCount complete initialized 64-byte blocks. The pointer
      // advances exactly once per validated block and never escapes. The
      // caller also retains the immutable initialized 256-byte constant table
      // for this synchronous call. Neither pointer escapes or crosses a
      // Sendable boundary.
      repeat {
        let savedState0 = state0
        let savedState1 = state1
        let messages = loadMessages(from: block)
        let compressed = compressBlock(
          state0: state0,
          state1: state1,
          message0: messages.0,
          message1: messages.1,
          message2: messages.2,
          message3: messages.3,
          constantTable: constantTable
        )
        state0 = vaddq_u32(compressed.0, savedState0)
        state1 = vaddq_u32(compressed.1, savedState1)
        block = block.advanced(by: 64)
        remainingBlockCount &-= 1
      } while remainingBlockCount != 0

      let savedState0 = state0
      let savedState1 = state1
      let padding = compressAlignedPaddingBlock(
        state0: state0,
        state1: state1,
        bitCount: bitCount,
        constantTable: constantTable
      )
      return (
        vaddq_u32(padding.0, savedState0),
        vaddq_u32(padding.1, savedState1)
      )
    }

    @inline(never)
    private static func compressMultipleBlockPairs(
      firstState0 initialFirstState0: SIMD4<UInt32>,
      firstState1 initialFirstState1: SIMD4<UInt32>,
      secondState0 initialSecondState0: SIMD4<UInt32>,
      secondState1 initialSecondState1: SIMD4<UInt32>,
      firstBlocks: UnsafeRawPointer,
      secondBlocks: UnsafeRawPointer,
      blockCount: Int,
      constantTableAddress: VolatileMappedRegister<UInt64>
    ) -> (
      SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>
    ) {
      var firstState0 = initialFirstState0
      var firstState1 = initialFirstState1
      var secondState0 = initialSecondState0
      var secondState1 = initialSecondState1
      var firstBlock = firstBlocks
      var secondBlock = secondBlocks
      var remainingBlockCount = blockCount

      // Unsafe invariants: the synchronous caller retains both memory owners
      // and supplies blockCount initialized 64-byte blocks in each range.
      // Both pointers advance by one validated block per iteration, use only
      // unaligned read-only byte loads, and never escape. The caller also owns
      // one initialized UInt64 containing the shared constant table's nonzero
      // address for the complete synchronous borrow. Its volatile load
      // recreates that same pointer inside every iteration and keeps the
      // 256-byte table loads in the loop.
      repeat {
        let savedFirstState0 = firstState0
        let savedFirstState1 = firstState1
        let savedSecondState0 = secondState0
        let savedSecondState1 = secondState1
        let blockConstantTable = UnsafeRawPointer(
          bitPattern: UInt(constantTableAddress.load())
        ).unsafelyUnwrapped
        let firstMessages = loadMessages(from: firstBlock)
        let secondMessages = loadMessages(from: secondBlock)
        let compressed = compressBlockPair(
          firstState0: firstState0,
          firstState1: firstState1,
          secondState0: secondState0,
          secondState1: secondState1,
          firstMessage0: firstMessages.0,
          firstMessage1: firstMessages.1,
          firstMessage2: firstMessages.2,
          firstMessage3: firstMessages.3,
          secondMessage0: secondMessages.0,
          secondMessage1: secondMessages.1,
          secondMessage2: secondMessages.2,
          secondMessage3: secondMessages.3,
          constantTable: blockConstantTable
        )
        firstState0 = vaddq_u32(compressed.0, savedFirstState0)
        firstState1 = vaddq_u32(compressed.1, savedFirstState1)
        secondState0 = vaddq_u32(compressed.2, savedSecondState0)
        secondState1 = vaddq_u32(compressed.3, savedSecondState1)
        firstBlock = firstBlock.advanced(by: 64)
        secondBlock = secondBlock.advanced(by: 64)
        remainingBlockCount &-= 1
      } while remainingBlockCount != 0

      return (firstState0, firstState1, secondState0, secondState1)
    }

    @inline(__always)
    private static func compressBlock(
      state0 initialState0: SIMD4<UInt32>,
      state1 initialState1: SIMD4<UInt32>,
      message0 initialMessage0: SIMD4<UInt32>,
      message1 initialMessage1: SIMD4<UInt32>,
      message2 initialMessage2: SIMD4<UInt32>,
      message3 initialMessage3: SIMD4<UInt32>,
      constantTable: UnsafeRawPointer
    ) -> (SIMD4<UInt32>, SIMD4<UInt32>) {
      var state0 = initialState0
      var state1 = initialState1
      var message0 = initialMessage0
      var message1 = initialMessage1
      var message2 = initialMessage2
      var message3 = initialMessage3

      // The static fixed-size table owns 256 initialized bytes throughout the
      // synchronous borrow. Every unaligned vector load is within that range,
      // does not mutate or rebind memory, and the pointer never escapes.
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: &message1,
        message2: &message2,
        message3: &message3,
        constants0: loadConstants(from: constantTable, at: 0),
        constants1: loadConstants(from: constantTable, at: 16)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 32),
        constants1: loadConstants(from: constantTable, at: 48)
      )

      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: &message1,
        message2: &message2,
        message3: &message3,
        constants0: loadConstants(from: constantTable, at: 64),
        constants1: loadConstants(from: constantTable, at: 80)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 96),
        constants1: loadConstants(from: constantTable, at: 112)
      )

      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: &message1,
        message2: &message2,
        message3: &message3,
        constants0: loadConstants(from: constantTable, at: 128),
        constants1: loadConstants(from: constantTable, at: 144)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 160),
        constants1: loadConstants(from: constantTable, at: 176)
      )

      twoFourRounds(
        state0: &state0,
        state1: &state1,
        message0: message0,
        message1: message1,
        constants0: loadConstants(from: constantTable, at: 192),
        constants1: loadConstants(from: constantTable, at: 208)
      )
      twoFourRounds(
        state0: &state0,
        state1: &state1,
        message0: message2,
        message1: message3,
        constants0: loadConstants(from: constantTable, at: 224),
        constants1: loadConstants(from: constantTable, at: 240)
      )

      return (state0, state1)
    }

    @inline(__always)
    private static func compressAlignedPaddingBlock(
      state0 initialState0: SIMD4<UInt32>,
      state1 initialState1: SIMD4<UInt32>,
      bitCount: UInt64,
      constantTable: UnsafeRawPointer
    ) -> (SIMD4<UInt32>, SIMD4<UInt32>) {
      var state0 = initialState0
      var state1 = initialState1
      var message0 = SIMD4<UInt32>(0x8000_0000, 0, 0, 0)
      var message1 = SIMD4<UInt32>(repeating: 0)
      var message2 = SIMD4<UInt32>(repeating: 0)
      var message3 = SIMD4<UInt32>(
        0, 0,
        UInt32(truncatingIfNeeded: bitCount >> 32),
        UInt32(truncatingIfNeeded: bitCount)
      )

      // For a full-block input, the final block always begins with the marker
      // and fourteen zero words. SHA256SU0(message0, message1) therefore leaves
      // message0 unchanged, and SHA256SU0(message1, message2) leaves message1
      // unchanged. Folding the marker into K[0] also removes the first vector
      // addition. These identities hold for every bitCount accepted here.
      fourRoundsPrepared(
        state0: &state0,
        state1: &state1,
        work: SIMD4(
          0xC28A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5
        )
      )
      message0 = vsha256su1q_u32(message0, message2, message3)

      fourRoundsPrepared(
        state0: &state0,
        state1: &state1,
        work: loadConstants(from: constantTable, at: 16)
      )
      message1 = vsha256su1q_u32(message1, message3, message0)

      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 32),
        constants1: loadConstants(from: constantTable, at: 48)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: &message1,
        message2: &message2,
        message3: &message3,
        constants0: loadConstants(from: constantTable, at: 64),
        constants1: loadConstants(from: constantTable, at: 80)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 96),
        constants1: loadConstants(from: constantTable, at: 112)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: &message1,
        message2: &message2,
        message3: &message3,
        constants0: loadConstants(from: constantTable, at: 128),
        constants1: loadConstants(from: constantTable, at: 144)
      )
      twoFourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: &message3,
        message2: &message0,
        message3: &message1,
        constants0: loadConstants(from: constantTable, at: 160),
        constants1: loadConstants(from: constantTable, at: 176)
      )
      twoFourRounds(
        state0: &state0,
        state1: &state1,
        message0: message0,
        message1: message1,
        constants0: loadConstants(from: constantTable, at: 192),
        constants1: loadConstants(from: constantTable, at: 208)
      )
      twoFourRounds(
        state0: &state0,
        state1: &state1,
        message0: message2,
        message1: message3,
        constants0: loadConstants(from: constantTable, at: 224),
        constants1: loadConstants(from: constantTable, at: 240)
      )

      return (state0, state1)
    }

    @inline(__always)
    private static func compressBlockPair(
      firstState0 initialFirstState0: SIMD4<UInt32>,
      firstState1 initialFirstState1: SIMD4<UInt32>,
      secondState0 initialSecondState0: SIMD4<UInt32>,
      secondState1 initialSecondState1: SIMD4<UInt32>,
      firstMessage0 initialFirstMessage0: SIMD4<UInt32>,
      firstMessage1 initialFirstMessage1: SIMD4<UInt32>,
      firstMessage2 initialFirstMessage2: SIMD4<UInt32>,
      firstMessage3 initialFirstMessage3: SIMD4<UInt32>,
      secondMessage0 initialSecondMessage0: SIMD4<UInt32>,
      secondMessage1 initialSecondMessage1: SIMD4<UInt32>,
      secondMessage2 initialSecondMessage2: SIMD4<UInt32>,
      secondMessage3 initialSecondMessage3: SIMD4<UInt32>,
      constantTable: UnsafeRawPointer
    ) -> (
      SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>
    ) {
      var firstState0 = initialFirstState0
      var firstState1 = initialFirstState1
      var secondState0 = initialSecondState0
      var secondState1 = initialSecondState1
      var firstMessage0 = initialFirstMessage0
      var firstMessage1 = initialFirstMessage1
      var firstMessage2 = initialFirstMessage2
      var firstMessage3 = initialFirstMessage3
      var secondMessage0 = initialSecondMessage0
      var secondMessage1 = initialSecondMessage1
      var secondMessage2 = initialSecondMessage2
      var secondMessage3 = initialSecondMessage3

      // The static fixed-size table owns 256 initialized bytes throughout the
      // synchronous borrow. Every unaligned vector load is within that range,
      // does not mutate or rebind memory, and the pointer never escapes.
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage0,
        firstMessage1: &firstMessage1,
        firstMessage2: &firstMessage2,
        firstMessage3: &firstMessage3,
        secondMessage0: &secondMessage0,
        secondMessage1: &secondMessage1,
        secondMessage2: &secondMessage2,
        secondMessage3: &secondMessage3,
        constants0: loadConstants(from: constantTable, at: 0),
        constants1: loadConstants(from: constantTable, at: 16)
      )
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage2,
        firstMessage1: &firstMessage3,
        firstMessage2: &firstMessage0,
        firstMessage3: &firstMessage1,
        secondMessage0: &secondMessage2,
        secondMessage1: &secondMessage3,
        secondMessage2: &secondMessage0,
        secondMessage3: &secondMessage1,
        constants0: loadConstants(from: constantTable, at: 32),
        constants1: loadConstants(from: constantTable, at: 48)
      )
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage0,
        firstMessage1: &firstMessage1,
        firstMessage2: &firstMessage2,
        firstMessage3: &firstMessage3,
        secondMessage0: &secondMessage0,
        secondMessage1: &secondMessage1,
        secondMessage2: &secondMessage2,
        secondMessage3: &secondMessage3,
        constants0: loadConstants(from: constantTable, at: 64),
        constants1: loadConstants(from: constantTable, at: 80)
      )
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage2,
        firstMessage1: &firstMessage3,
        firstMessage2: &firstMessage0,
        firstMessage3: &firstMessage1,
        secondMessage0: &secondMessage2,
        secondMessage1: &secondMessage3,
        secondMessage2: &secondMessage0,
        secondMessage3: &secondMessage1,
        constants0: loadConstants(from: constantTable, at: 96),
        constants1: loadConstants(from: constantTable, at: 112)
      )
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage0,
        firstMessage1: &firstMessage1,
        firstMessage2: &firstMessage2,
        firstMessage3: &firstMessage3,
        secondMessage0: &secondMessage0,
        secondMessage1: &secondMessage1,
        secondMessage2: &secondMessage2,
        secondMessage3: &secondMessage3,
        constants0: loadConstants(from: constantTable, at: 128),
        constants1: loadConstants(from: constantTable, at: 144)
      )
      twoFourRoundsPairAndAdvance(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage2,
        firstMessage1: &firstMessage3,
        firstMessage2: &firstMessage0,
        firstMessage3: &firstMessage1,
        secondMessage0: &secondMessage2,
        secondMessage1: &secondMessage3,
        secondMessage2: &secondMessage0,
        secondMessage3: &secondMessage1,
        constants0: loadConstants(from: constantTable, at: 160),
        constants1: loadConstants(from: constantTable, at: 176)
      )
      twoFourRoundsPair(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: firstMessage0,
        firstMessage1: firstMessage1,
        secondMessage0: secondMessage0,
        secondMessage1: secondMessage1,
        constants0: loadConstants(from: constantTable, at: 192),
        constants1: loadConstants(from: constantTable, at: 208)
      )
      twoFourRoundsPair(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: firstMessage2,
        firstMessage1: firstMessage3,
        secondMessage0: secondMessage2,
        secondMessage1: secondMessage3,
        constants0: loadConstants(from: constantTable, at: 224),
        constants1: loadConstants(from: constantTable, at: 240)
      )

      return (firstState0, firstState1, secondState0, secondState1)
    }

    @inline(__always)
    private static func loadConstants(
      from constantTable: UnsafeRawPointer,
      at byteOffset: Int
    ) -> SIMD4<UInt32> {
      constantTable.advanced(by: byteOffset).loadUnaligned(as: SIMD4<UInt32>.self)
    }

    @inline(__always)
    private static func storeState(
      _ state0: SIMD4<UInt32>,
      _ state1: SIMD4<UInt32>,
      into state: inout SIMD8<UInt32>
    ) {
      state = SIMD8(
        state0[0], state0[1], state0[2], state0[3],
        state1[0], state1[1], state1[2], state1[3]
      )
    }

    @inline(__always)
    private static func twoFourRoundsPair(
      firstState0: inout SIMD4<UInt32>,
      firstState1: inout SIMD4<UInt32>,
      secondState0: inout SIMD4<UInt32>,
      secondState1: inout SIMD4<UInt32>,
      firstMessage0: SIMD4<UInt32>,
      firstMessage1: SIMD4<UInt32>,
      secondMessage0: SIMD4<UInt32>,
      secondMessage1: SIMD4<UInt32>,
      constants0: SIMD4<UInt32>,
      constants1: SIMD4<UInt32>
    ) {
      fourRoundsPairPrepared(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstWork: vaddq_u32(firstMessage0, constants0),
        secondWork: vaddq_u32(secondMessage0, constants0)
      )
      fourRoundsPairPrepared(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstWork: vaddq_u32(firstMessage1, constants1),
        secondWork: vaddq_u32(secondMessage1, constants1)
      )
    }

    @inline(__always)
    private static func fourRoundsPairPrepared(
      firstState0: inout SIMD4<UInt32>,
      firstState1: inout SIMD4<UInt32>,
      secondState0: inout SIMD4<UInt32>,
      secondState1: inout SIMD4<UInt32>,
      firstWork: SIMD4<UInt32>,
      secondWork: SIMD4<UInt32>
    ) {
      let previousFirstState0 = firstState0
      let previousSecondState0 = secondState0
      firstState0 = vsha256hq_u32(firstState0, firstState1, firstWork)
      secondState0 = vsha256hq_u32(secondState0, secondState1, secondWork)
      firstState1 = vsha256h2q_u32(
        firstState1,
        previousFirstState0,
        firstWork
      )
      secondState1 = vsha256h2q_u32(
        secondState1,
        previousSecondState0,
        secondWork
      )
    }

    @inline(__always)
    private static func twoFourRoundsPairAndAdvance(
      firstState0: inout SIMD4<UInt32>,
      firstState1: inout SIMD4<UInt32>,
      secondState0: inout SIMD4<UInt32>,
      secondState1: inout SIMD4<UInt32>,
      firstMessage0: inout SIMD4<UInt32>,
      firstMessage1: inout SIMD4<UInt32>,
      firstMessage2: inout SIMD4<UInt32>,
      firstMessage3: inout SIMD4<UInt32>,
      secondMessage0: inout SIMD4<UInt32>,
      secondMessage1: inout SIMD4<UInt32>,
      secondMessage2: inout SIMD4<UInt32>,
      secondMessage3: inout SIMD4<UInt32>,
      constants0: SIMD4<UInt32>,
      constants1: SIMD4<UInt32>
    ) {
      fourRoundsPairAndAdvancePrepared(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage0,
        firstMessage1: firstMessage1,
        firstMessage2: firstMessage2,
        firstMessage3: firstMessage3,
        secondMessage0: &secondMessage0,
        secondMessage1: secondMessage1,
        secondMessage2: secondMessage2,
        secondMessage3: secondMessage3,
        firstWork: vaddq_u32(firstMessage0, constants0),
        secondWork: vaddq_u32(secondMessage0, constants0)
      )
      fourRoundsPairAndAdvancePrepared(
        firstState0: &firstState0,
        firstState1: &firstState1,
        secondState0: &secondState0,
        secondState1: &secondState1,
        firstMessage0: &firstMessage1,
        firstMessage1: firstMessage2,
        firstMessage2: firstMessage3,
        firstMessage3: firstMessage0,
        secondMessage0: &secondMessage1,
        secondMessage1: secondMessage2,
        secondMessage2: secondMessage3,
        secondMessage3: secondMessage0,
        firstWork: vaddq_u32(firstMessage1, constants1),
        secondWork: vaddq_u32(secondMessage1, constants1)
      )
    }

    @inline(__always)
    private static func fourRoundsPairAndAdvancePrepared(
      firstState0: inout SIMD4<UInt32>,
      firstState1: inout SIMD4<UInt32>,
      secondState0: inout SIMD4<UInt32>,
      secondState1: inout SIMD4<UInt32>,
      firstMessage0: inout SIMD4<UInt32>,
      firstMessage1: SIMD4<UInt32>,
      firstMessage2: SIMD4<UInt32>,
      firstMessage3: SIMD4<UInt32>,
      secondMessage0: inout SIMD4<UInt32>,
      secondMessage1: SIMD4<UInt32>,
      secondMessage2: SIMD4<UInt32>,
      secondMessage3: SIMD4<UInt32>,
      firstWork: SIMD4<UInt32>,
      secondWork: SIMD4<UInt32>
    ) {
      let firstHalf = vsha256su0q_u32(firstMessage0, firstMessage1)
      let secondHalf = vsha256su0q_u32(secondMessage0, secondMessage1)
      let previousFirstState0 = firstState0
      let previousSecondState0 = secondState0
      firstState0 = vsha256hq_u32(firstState0, firstState1, firstWork)
      secondState0 = vsha256hq_u32(secondState0, secondState1, secondWork)
      firstState1 = vsha256h2q_u32(
        firstState1,
        previousFirstState0,
        firstWork
      )
      secondState1 = vsha256h2q_u32(
        secondState1,
        previousSecondState0,
        secondWork
      )
      firstMessage0 = vsha256su1q_u32(
        firstHalf,
        firstMessage2,
        firstMessage3
      )
      secondMessage0 = vsha256su1q_u32(
        secondHalf,
        secondMessage2,
        secondMessage3
      )
    }

    @inline(__always)
    private static func twoFourRounds(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message0: SIMD4<UInt32>,
      message1: SIMD4<UInt32>,
      constants0: SIMD4<UInt32>,
      constants1: SIMD4<UInt32>
    ) {
      let work0 = vaddq_u32(message0, constants0)
      fourRoundsPrepared(state0: &state0, state1: &state1, work: work0)
      let work1 = vaddq_u32(message1, constants1)
      fourRoundsPrepared(state0: &state0, state1: &state1, work: work1)
    }

    @inline(__always)
    private static func fourRoundsPrepared(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      work: SIMD4<UInt32>
    ) {
      // The ABI duplication boundary keeps feed-forward state outside the
      // working pair. Saving old H before updating it lets LLVM retain H/H2
      // in q0/q1 and materialize the one rotating copy required by ARMv8 SHA2.
      let previousState0 = state0
      state0 = vsha256hq_u32(state0, state1, work)
      state1 = vsha256h2q_u32(state1, previousState0, work)
    }

    @inline(__always)
    private static func twoFourRoundsAndAdvance(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message0: inout SIMD4<UInt32>,
      message1: inout SIMD4<UInt32>,
      message2: inout SIMD4<UInt32>,
      message3: inout SIMD4<UInt32>,
      constants0: SIMD4<UInt32>,
      constants1: SIMD4<UInt32>
    ) {
      let work0 = vaddq_u32(message0, constants0)
      fourRoundsAndAdvancePrepared(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: message1,
        message2: message2,
        message3: message3,
        work: work0
      )
      let work1 = vaddq_u32(message1, constants1)
      fourRoundsAndAdvancePrepared(
        state0: &state0,
        state1: &state1,
        message0: &message1,
        message1: message2,
        message2: message3,
        message3: message0,
        work: work1
      )
    }

    @inline(__always)
    private static func fourRoundsAndAdvancePrepared(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message0: inout SIMD4<UInt32>,
      message1: SIMD4<UInt32>,
      message2: SIMD4<UInt32>,
      message3: SIMD4<UInt32>,
      work: SIMD4<UInt32>
    ) {
      let firstHalf = vsha256su0q_u32(message0, message1)
      let previousState0 = state0
      state0 = vsha256hq_u32(state0, state1, work)
      state1 = vsha256h2q_u32(state1, previousState0, work)
      message0 = vsha256su1q_u32(firstHalf, message2, message3)
    }

    @inline(__always)
    private static func loadMessages(
      from block: UnsafeRawPointer
    ) -> (
      SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>, SIMD4<UInt32>
    ) {
      // Unsafe invariants: the synchronous caller owns 64 initialized bytes.
      // ARMv8 LD1 reads that exact range without an alignment requirement,
      // binding, or mutation. The raw pointer and loaded values do not escape.
      let vectors = loadFourSHA256Vectors(block)
      return (
        vreinterpretq_u32_u8(
          vrev32q_u8(vreinterpretq_u8_u32(vectors.0))
        ),
        vreinterpretq_u32_u8(
          vrev32q_u8(vreinterpretq_u8_u32(vectors.1))
        ),
        vreinterpretq_u32_u8(
          vrev32q_u8(vreinterpretq_u8_u32(vectors.2))
        ),
        vreinterpretq_u32_u8(
          vrev32q_u8(vreinterpretq_u8_u32(vectors.3))
        )
      )
    }
  }
#endif
