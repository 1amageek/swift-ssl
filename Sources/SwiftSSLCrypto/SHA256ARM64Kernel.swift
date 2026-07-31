#if os(macOS) && arch(arm64) && canImport(simd)
  import simd

  enum SHA256ARM64Kernel {
    @inline(__always)
    static func compressBlocks(
      state: inout SIMD8<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int
    ) {
      var state0 = SIMD4<UInt32>(
        state[0], state[1], state[2], state[3]
      )
      var state1 = SIMD4<UInt32>(
        state[4], state[5], state[6], state[7]
      )

      if blockCount == 1 {
        compressBlock(
          state0: &state0,
          state1: &state1,
          message0: loadMessage(from: blocks, at: 0),
          message1: loadMessage(from: blocks, at: 16),
          message2: loadMessage(from: blocks, at: 32),
          message3: loadMessage(from: blocks, at: 48)
        )
        storeState(state0, state1, into: &state)
        return
      }

      (state0, state1) = compressMultipleBlocks(
        state0: state0,
        state1: state1,
        blocks: blocks,
        blockCount: blockCount
      )

      storeState(state0, state1, into: &state)
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

      compressBlock(
        state0: &state0,
        state1: &state1,
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
        )
      )
      storeState(state0, state1, into: &state)
    }

    @inline(never)
    private static func compressMultipleBlocks(
      state0 initialState0: SIMD4<UInt32>,
      state1 initialState1: SIMD4<UInt32>,
      blocks: UnsafeRawPointer,
      blockCount: Int
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
      // mutated. The derived pointer does not escape or cross Sendable.
      while remainingBlockCount > 0 {
        compressBlock(
          state0: &state0,
          state1: &state1,
          message0: loadMessage(from: block, at: 0),
          message1: loadMessage(from: block, at: 16),
          message2: loadMessage(from: block, at: 32),
          message3: loadMessage(from: block, at: 48)
        )
        block = block.advanced(by: 64)
        remainingBlockCount -= 1
      }
      return (state0, state1)
    }

    @inline(__always)
    private static func compressBlock(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message0 initialMessage0: SIMD4<UInt32>,
      message1 initialMessage1: SIMD4<UInt32>,
      message2 initialMessage2: SIMD4<UInt32>,
      message3 initialMessage3: SIMD4<UInt32>
    ) {
      let savedState0 = state0
      let savedState1 = state1

      var message0 = initialMessage0
      var message1 = initialMessage1
      var message2 = initialMessage2
      var message3 = initialMessage3

      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: message1,
        message2: message2,
        message3: message3,
        constants: SIMD4(0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message1,
        message1: message2,
        message2: message3,
        message3: message0,
        constants: SIMD4(0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: message3,
        message2: message0,
        message3: message1,
        constants: SIMD4(0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message3,
        message1: message0,
        message2: message1,
        message3: message2,
        constants: SIMD4(0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174)
      )

      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: message1,
        message2: message2,
        message3: message3,
        constants: SIMD4(0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message1,
        message1: message2,
        message2: message3,
        message3: message0,
        constants: SIMD4(0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: message3,
        message2: message0,
        message3: message1,
        constants: SIMD4(0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message3,
        message1: message0,
        message2: message1,
        message3: message2,
        constants: SIMD4(0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967)
      )

      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message0,
        message1: message1,
        message2: message2,
        message3: message3,
        constants: SIMD4(0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message1,
        message1: message2,
        message2: message3,
        message3: message0,
        constants: SIMD4(0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message2,
        message1: message3,
        message2: message0,
        message3: message1,
        constants: SIMD4(0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3)
      )
      fourRoundsAndAdvance(
        state0: &state0,
        state1: &state1,
        message0: &message3,
        message1: message0,
        message2: message1,
        message3: message2,
        constants: SIMD4(0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070)
      )

      fourRounds(
        state0: &state0,
        state1: &state1,
        message: message0,
        constants: SIMD4(0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5)
      )
      fourRounds(
        state0: &state0,
        state1: &state1,
        message: message1,
        constants: SIMD4(0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3)
      )
      fourRounds(
        state0: &state0,
        state1: &state1,
        message: message2,
        constants: SIMD4(0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208)
      )
      fourRounds(
        state0: &state0,
        state1: &state1,
        message: message3,
        constants: SIMD4(0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2)
      )

      state0 = vaddq_u32(state0, savedState0)
      state1 = vaddq_u32(state1, savedState1)
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
    private static func fourRounds(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message: SIMD4<UInt32>,
      constants: SIMD4<UInt32>
    ) {
      let work = vaddq_u32(message, constants)
      let previousState0 = state0
      state0 = vsha256hq_u32(state0, state1, work)
      state1 = vsha256h2q_u32(state1, previousState0, work)
    }

    @inline(__always)
    private static func fourRoundsAndAdvance(
      state0: inout SIMD4<UInt32>,
      state1: inout SIMD4<UInt32>,
      message0: inout SIMD4<UInt32>,
      message1: SIMD4<UInt32>,
      message2: SIMD4<UInt32>,
      message3: SIMD4<UInt32>,
      constants: SIMD4<UInt32>
    ) {
      let work = vaddq_u32(message0, constants)
      let firstHalf = vsha256su0q_u32(message0, message1)
      let previousState0 = state0
      state0 = vsha256hq_u32(state0, state1, work)
      state1 = vsha256h2q_u32(state1, previousState0, work)
      message0 = vsha256su1q_u32(firstHalf, message2, message3)
    }

    @inline(__always)
    private static func loadMessage(
      from block: UnsafeRawPointer,
      at byteOffset: Int
    ) -> SIMD4<UInt32> {
      let address = block.advanced(by: byteOffset)
      let alignmentMask = UInt(MemoryLayout<SIMD4<UInt32>>.alignment - 1)
      let words: SIMD4<UInt32>
      if UInt(bitPattern: address) & alignmentMask == 0 {
        words = address.load(as: SIMD4<UInt32>.self)
      } else {
        var unalignedWords = SIMD4<UInt32>(repeating: 0)
        withUnsafeMutableBytes(of: &unalignedWords) { destination in
          destination.copyMemory(
            from: UnsafeRawBufferPointer(
              start: address,
              count: MemoryLayout<SIMD4<UInt32>>.size
            )
          )
        }
        words = unalignedWords
      }
      return vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(words))
      )
    }
  }
#endif
