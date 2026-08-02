import SwiftSSLCore

/// AES encryption for the block primitive used by the GCM construction.
///
/// The type owns its expanded key schedule. Callers must validate that both
/// spans contain exactly one AES block before entering this internal boundary.
struct AESBlockCipher: ~Copyable {
  #if arch(arm64) && canImport(simd)
    private var hardwareRoundKeys: SIMD64<UInt32>
  #else
    private var roundKeys: SIMD64<UInt32>
  #endif
  let roundCount: Int

  init(key: Span<UInt8>) {
    let wordCount = key.count / 4
    let roundCount = wordCount + 6

    var words = SIMD64<UInt32>(repeating: 0)
    defer {
      withUnsafeMutableBytes(of: &words) { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        SecureWipe.erase(baseAddress, byteCount: bytes.count)
      }
    }
    let expandedWordCount = 4 * (roundCount + 1)
    var index = 0
    while index < wordCount {
      let offset = index * 4
      words[index] =
        (UInt32(key[unchecked: offset]) << 24)
        | (UInt32(key[unchecked: offset + 1]) << 16)
        | (UInt32(key[unchecked: offset + 2]) << 8)
        | UInt32(key[unchecked: offset + 3])
      index += 1
    }

    var next = wordCount
    var rcon: UInt8 = 1
    while next < expandedWordCount {
      var word = words[next - 1]
      if next % wordCount == 0 {
        word = Self.subWord(Self.rotatedWord(word)) ^ (UInt32(rcon) << 24)
        rcon = Self.xtime(rcon)
      } else if wordCount == 8 && next % wordCount == 4 {
        word = Self.subWord(word)
      }
      words[next] = words[next - wordCount] ^ word
      next += 1
    }

    #if arch(arm64) && canImport(simd)
      var hardwareRoundKeys = SIMD64<UInt32>(repeating: 0)
      var round = 0
      while round <= roundCount {
        var column = 0
        while column < 4 {
          hardwareRoundKeys[round * 4 + column] =
            words[round * 4 + column].byteSwapped
          column += 1
        }
        round += 1
      }
      self.hardwareRoundKeys = hardwareRoundKeys
    #else
      self.roundKeys = words
    #endif
    self.roundCount = roundCount
  }

  func encrypt(_ input: Span<UInt8>, into output: inout MutableSpan<UInt8>) {
    #if arch(arm64) && canImport(simd)
      AESARM64Kernel.encrypt(
        input,
        into: &output,
        roundKeys: hardwareRoundKeys,
        roundCount: roundCount
      )
    #else
      var state = SIMD16<UInt8>(repeating: 0)
      var index = 0
      while index < 16 {
        state[index] = input[index]
        index += 1
      }

      addRoundKey(&state, round: 0)
      var round = 1
      while round < roundCount {
        substituteBytes(&state)
        shiftRows(&state)
        mixColumns(&state)
        addRoundKey(&state, round: round)
        round += 1
      }
      substituteBytes(&state)
      shiftRows(&state)
      addRoundKey(&state, round: roundCount)

      index = 0
      while index < 16 {
        output[index] = state[index]
        index += 1
      }
    #endif
  }

  #if arch(arm64) && canImport(simd)
    @inline(__always)
    func xorFourCounters(
      _ input: Span<UInt8>,
      at offset: Int,
      startingAt counter: SIMD16<UInt8>,
      into output: inout MutableSpan<UInt8>
    ) {
      AESARM64Kernel.xorFourCounters(
        input,
        at: offset,
        startingAt: counter,
        into: &output,
        roundKeys: hardwareRoundKeys,
        roundCount: roundCount
      )
    }
  #endif

  #if !arch(arm64) || !canImport(simd)
    private func addRoundKey(_ state: inout SIMD16<UInt8>, round: Int) {
      let base = round * 4
      var column = 0
      while column < 4 {
        let word = roundKeys[base + column]
        let offset = column * 4
        state[offset] ^= UInt8(truncatingIfNeeded: word >> 24)
        state[offset + 1] ^= UInt8(truncatingIfNeeded: word >> 16)
        state[offset + 2] ^= UInt8(truncatingIfNeeded: word >> 8)
        state[offset + 3] ^= UInt8(truncatingIfNeeded: word)
        column += 1
      }
    }
  #endif

  private func substituteBytes(_ state: inout SIMD16<UInt8>) {
    var index = 0
    while index < 16 {
      state[index] = sBox[Int(state[index])]
      index += 1
    }
  }

  private func shiftRows(_ state: inout SIMD16<UInt8>) {
    state = SIMD16(
      state[0], state[5], state[10], state[15],
      state[4], state[9], state[14], state[3],
      state[8], state[13], state[2], state[7],
      state[12], state[1], state[6], state[11]
    )
  }

  private func mixColumns(_ state: inout SIMD16<UInt8>) {
    var column = 0
    while column < 4 {
      let offset = column * 4
      let a0 = state[offset]
      let a1 = state[offset + 1]
      let a2 = state[offset + 2]
      let a3 = state[offset + 3]
      state[offset] = Self.gmul2(a0) ^ Self.gmul3(a1) ^ a2 ^ a3
      state[offset + 1] = a0 ^ Self.gmul2(a1) ^ Self.gmul3(a2) ^ a3
      state[offset + 2] = a0 ^ a1 ^ Self.gmul2(a2) ^ Self.gmul3(a3)
      state[offset + 3] = Self.gmul3(a0) ^ a1 ^ a2 ^ Self.gmul2(a3)
      column += 1
    }
  }

  private static func rotatedWord(_ word: UInt32) -> UInt32 {
    (word << 8) | (word >> 24)
  }

  private static func subWord(_ word: UInt32) -> UInt32 {
    #if arch(arm64) && canImport(simd)
      AESARM64Kernel.subWord(word)
    #else
      (UInt32(sBox[Int((word >> 24) & 0xff)]) << 24)
        | (UInt32(sBox[Int((word >> 16) & 0xff)]) << 16)
        | (UInt32(sBox[Int((word >> 8) & 0xff)]) << 8)
        | UInt32(sBox[Int(word & 0xff)])
    #endif
  }

  private static func xtime(_ value: UInt8) -> UInt8 {
    let shifted = value << 1
    return (value & 0x80) == 0 ? shifted : shifted ^ 0x1b
  }

  private static func gmul2(_ value: UInt8) -> UInt8 {
    xtime(value)
  }

  private static func gmul3(_ value: UInt8) -> UInt8 {
    gmul2(value) ^ value
  }

  deinit {
    // Unsafe boundary invariants:
    // - AESBlockCipher is noncopyable, so destruction wipes its unique inline
    //   key schedule exactly once.
    // - Each SIMD64 contains exactly 64 initialized UInt32 lanes.
    // - deinit exposes self immutably, but no live alias can observe the unique
    //   noncopyable value; the scoped mutating raw pointer is used only to wipe.
    #if arch(arm64) && canImport(simd)
      withUnsafeBytes(of: hardwareRoundKeys) { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        SecureWipe.erase(
          UnsafeMutableRawPointer(mutating: baseAddress),
          byteCount: bytes.count
        )
      }
    #else
      withUnsafeBytes(of: roundKeys) { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        SecureWipe.erase(
          UnsafeMutableRawPointer(mutating: baseAddress),
          byteCount: bytes.count
        )
      }
    #endif
  }
}

private let sBox: [UInt8] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
