#if arch(arm64) && canImport(simd)
  import SwiftSSLCore
  import simd

  enum AESARM64Kernel {
    /// Applies the AES S-box to all four bytes of a key-schedule word without
    /// secret-dependent memory access.
    @inline(__always)
    static func subWord(_ word: UInt32) -> UInt32 {
      // Unsafe bit-cast invariants:
      // - SIMD4<UInt32> and SIMD16<UInt8> are both fixed 16-byte values.
      // - Both source values are fully initialized value types. No pointer,
      //   storage binding, aliasing, ownership transfer, or deallocation is
      //   involved, and no borrow escapes this synchronous function.
      // - The word is byte-swapped before duplication so each vector column
      //   contains the key schedule's big-endian byte order.
      // - Repeating the same word in all four columns makes AES ShiftRows a
      //   no-op for the value of each column, leaving only SubBytes.
      let columns = SIMD4<UInt32>(repeating: word.byteSwapped)
      let bytes = unsafeBitCast(columns, to: SIMD16<UInt8>.self)
      let substituted = vaeseq_u8(bytes, SIMD16<UInt8>(repeating: 0))
      let result = unsafeBitCast(substituted, to: SIMD4<UInt32>.self)
      return result[0].byteSwapped
    }

    @inline(__always)
    static func encrypt(
      _ input: Span<UInt8>,
      into output: inout MutableSpan<UInt8>,
      roundKeys: borrowing SIMD64<UInt32>,
      roundCount: Int
    ) {
      precondition(input.count == 16)
      precondition(output.count >= 16)

      // Unsafe boundary invariants:
      // - roundKeys owns 256 initialized bytes and every AES key schedule uses
      //   at most 15 consecutive 16-byte round keys.
      // - SIMD64<UInt32> has sufficient alignment for SIMD16<UInt8> loads.
      // - The rebound pointer is read-only, remains inside this synchronous
      //   closure, and does not overlap input or output mutation.
      withUnsafeBytes(of: roundKeys) { bytes in
        let keys = bytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: SIMD16<UInt8>.self)
        var state = loadUnaligned(input)
        var round = 0
        while round < roundCount - 1 {
          state = vaeseq_u8(state, keys[round])
          state = vaesmcq_u8(state)
          round += 1
        }
        state = vaeseq_u8(state, keys[roundCount - 1])
        state = veorq_u8(state, keys[roundCount])
        storeUnaligned(state, into: &output)
      }
    }

    /// Encrypts and XORs four consecutive GCM counter blocks directly into
    /// caller-owned output. Keeping four independent states in registers hides
    /// AES round latency and avoids a materialized keystream buffer.
    @inline(__always)
    static func xorFourCounters(
      _ input: Span<UInt8>,
      at offset: Int,
      startingAt counter: SIMD16<UInt8>,
      into output: inout MutableSpan<UInt8>,
      roundKeys: borrowing SIMD64<UInt32>,
      roundCount: Int
    ) {
      precondition(offset >= 0 && offset <= input.count - 64)
      precondition(offset <= output.count - 64)

      var state0 = counter
      let reversedWords = vreinterpretq_u32_u8(vrev32q_u8(counter))
      var state1 = vrev32q_u8(
        vreinterpretq_u8_u32(reversedWords &+ SIMD4(0, 0, 0, 1))
      )
      var state2 = vrev32q_u8(
        vreinterpretq_u8_u32(reversedWords &+ SIMD4(0, 0, 0, 2))
      )
      var state3 = vrev32q_u8(
        vreinterpretq_u8_u32(reversedWords &+ SIMD4(0, 0, 0, 3))
      )

      // Unsafe boundary invariants:
      // - The schedule owns 256 initialized bytes and is borrowed only for
      //   this synchronous call, with the same binding contract as `encrypt`.
      // - The validated offset exposes four initialized input blocks and four
      //   writable output blocks. Unaligned loads do not bind input storage.
      // - Output stores use aligned typed writes only when the runtime address
      //   satisfies SIMD alignment; otherwise byte copies preserve alignment.
      // - Exact input/output aliasing is supported because all four input
      //   vectors are loaded before any output byte is written.
      withUnsafeBytes(of: roundKeys) { keyBytes in
        let keys = keyBytes.baseAddress.unsafelyUnwrapped
          .assumingMemoryBound(to: SIMD16<UInt8>.self)
        var round = 0
        while round < roundCount - 1 {
          state0 = vaesmcq_u8(vaeseq_u8(state0, keys[round]))
          state1 = vaesmcq_u8(vaeseq_u8(state1, keys[round]))
          state2 = vaesmcq_u8(vaeseq_u8(state2, keys[round]))
          state3 = vaesmcq_u8(vaeseq_u8(state3, keys[round]))
          round += 1
        }
        state0 = veorq_u8(vaeseq_u8(state0, keys[roundCount - 1]), keys[roundCount])
        state1 = veorq_u8(vaeseq_u8(state1, keys[roundCount - 1]), keys[roundCount])
        state2 = veorq_u8(vaeseq_u8(state2, keys[roundCount - 1]), keys[roundCount])
        state3 = veorq_u8(vaeseq_u8(state3, keys[roundCount - 1]), keys[roundCount])
      }

      input.withUnsafeBytes { inputBytes in
        let inputBase = inputBytes.baseAddress.unsafelyUnwrapped
        state0 ^= inputBase.loadUnaligned(fromByteOffset: offset, as: SIMD16<UInt8>.self)
        state1 ^= inputBase.loadUnaligned(fromByteOffset: offset + 16, as: SIMD16<UInt8>.self)
        state2 ^= inputBase.loadUnaligned(fromByteOffset: offset + 32, as: SIMD16<UInt8>.self)
        state3 ^= inputBase.loadUnaligned(fromByteOffset: offset + 48, as: SIMD16<UInt8>.self)
      }
      output.withUnsafeMutableBytes { outputBytes in
        let outputBase = outputBytes.baseAddress.unsafelyUnwrapped.advanced(by: offset)
        storePossiblyUnaligned(state0, to: outputBase)
        storePossiblyUnaligned(state1, to: outputBase.advanced(by: 16))
        storePossiblyUnaligned(state2, to: outputBase.advanced(by: 32))
        storePossiblyUnaligned(state3, to: outputBase.advanced(by: 48))
      }
    }

    @inline(__always)
    static func advanceCounterByFour(_ counter: inout SIMD16<UInt8>) {
      let reversedWords = vreinterpretq_u32_u8(vrev32q_u8(counter))
      counter = vrev32q_u8(
        vreinterpretq_u8_u32(reversedWords &+ SIMD4(0, 0, 0, 4))
      )
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

    @inline(__always)
    private static func loadUnaligned(_ input: Span<UInt8>) -> SIMD16<UInt8> {
      input.withUnsafeBytes { bytes in
        guard let baseAddress = bytes.baseAddress else {
          preconditionFailure("AES input must contain one initialized block")
        }
        if UInt(bitPattern: baseAddress) & UInt(MemoryLayout<SIMD16<UInt8>>.alignment - 1) == 0 {
          return baseAddress.load(as: SIMD16<UInt8>.self)
        }
        var value = SIMD16<UInt8>(repeating: 0)
        withUnsafeMutableBytes(of: &value) { destination in
          destination.copyMemory(from: bytes)
        }
        return value
      }
    }

    @inline(__always)
    private static func storeUnaligned(
      _ value: SIMD16<UInt8>,
      into output: inout MutableSpan<UInt8>
    ) {
      output.withUnsafeMutableBytes { destination in
        guard let baseAddress = destination.baseAddress else {
          preconditionFailure("AES output must contain one writable block")
        }
        if UInt(bitPattern: baseAddress) & UInt(MemoryLayout<SIMD16<UInt8>>.alignment - 1) == 0 {
          baseAddress.storeBytes(of: value, as: SIMD16<UInt8>.self)
          return
        }
        var value = value
        withUnsafeBytes(of: &value) { source in
          destination.copyMemory(from: source)
        }
      }
    }
  }
#endif
