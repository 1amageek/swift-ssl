import SSLCore

/// Incremental SHA-1 context used only for compatibility with legacy protocols.
/// The state is value-owned and cloned before finalization, so the input context
/// remains usable until its caller discards it.
public struct SHA1Context: ~Copyable, HashContext, Sendable {
  public static let digestByteCount = 20
  private static let blockByteCount = 64
  private static let maximumInputByteCount = UInt64.max >> 3

  private var state: [UInt32]
  private var pendingBytes: SIMD64<UInt8>
  private var pendingByteCount: Int
  private var totalByteCount: UInt64

  public init() {
    state = [
      0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0
    ]
    pendingBytes = SIMD64<UInt8>(repeating: 0)
    pendingByteCount = 0
    totalByteCount = 0
  }

  private init(
    state: [UInt32],
    pendingBytes: SIMD64<UInt8>,
    pendingByteCount: Int,
    totalByteCount: UInt64
  ) {
    self.state = state
    self.pendingBytes = pendingBytes
    self.pendingByteCount = pendingByteCount
    self.totalByteCount = totalByteCount
  }

  public borrowing func clone() -> SHA1Context {
    SHA1Context(
      state: state,
      pendingBytes: pendingBytes,
      pendingByteCount: pendingByteCount,
      totalByteCount: totalByteCount
    )
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    let inputByteCount = UInt64(input.count)
    guard totalByteCount <= Self.maximumInputByteCount,
      inputByteCount <= Self.maximumInputByteCount - totalByteCount
    else {
      throw .inputTooLong(limit: Self.maximumInputByteCount)
    }
    totalByteCount += inputByteCount
    var offset = 0

    if pendingByteCount != 0 {
      let copied = Swift.min(Self.blockByteCount - pendingByteCount, input.count)
      var index = 0
      while index < copied {
        pendingBytes[pendingByteCount + index] = input[index]
        index += 1
      }
      pendingByteCount += copied
      offset += copied
      if pendingByteCount == Self.blockByteCount {
        compress(pendingBytes)
        pendingByteCount = 0
      }
    }

    while input.count - offset >= Self.blockByteCount {
      compress(input.extracting(offset..<(offset + Self.blockByteCount)))
      offset += Self.blockByteCount
    }

    let remaining = input.count - offset
    if remaining > 0 {
      var index = 0
      while index < remaining {
        pendingBytes[index] = input[offset + index]
        index += 1
      }
      pendingByteCount = remaining
    }
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try finalizeInPlace(into: &output)
  }

  package mutating func finalizeInPlace(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    var copy = self.clone()
    let bitCount = copy.totalByteCount << 3
    copy.pendingBytes[copy.pendingByteCount] = 0x80
    copy.pendingByteCount += 1
    if copy.pendingByteCount > 56 {
      copy.zeroPendingBytes(from: copy.pendingByteCount, to: 64)
      copy.compress(copy.pendingBytes)
      copy.pendingByteCount = 0
    }
    copy.zeroPendingBytes(from: copy.pendingByteCount, to: 56)
    var index = 0
    while index < 8 {
      let shift = UInt64((7 - index) * 8)
      copy.pendingBytes[56 + index] = UInt8(truncatingIfNeeded: bitCount >> shift)
      index += 1
    }
    copy.compress(copy.pendingBytes)
    index = 0
    while index < 5 {
      let word = copy.state[index]
      let offset = index * 4
      output[offset] = UInt8(truncatingIfNeeded: word >> 24)
      output[offset + 1] = UInt8(truncatingIfNeeded: word >> 16)
      output[offset + 2] = UInt8(truncatingIfNeeded: word >> 8)
      output[offset + 3] = UInt8(truncatingIfNeeded: word)
      index += 1
    }
    eraseSensitiveState()
  }

  @inline(__always)
  private mutating func zeroPendingBytes(from start: Int, to end: Int) {
    var index = start
    while index < end {
      pendingBytes[index] = 0
      index += 1
    }
  }

  private mutating func compress(_ block: Span<UInt8>) {
    block.bytes.withUnsafeBytes { bytes in
      compressBytes(bytes)
    }
  }

  private mutating func compress(_ block: SIMD64<UInt8>) {
    var block = block
    withUnsafeBytes(of: &block) { bytes in
      compressBytes(bytes)
    }
  }

  private mutating func compressBytes(_ block: UnsafeRawBufferPointer) {
    precondition(block.count == Self.blockByteCount)
    var words = [UInt32](repeating: 0, count: 80)
    var index = 0
    while index < 16 {
      let offset = index * 4
      words[index] = UInt32(block[offset]) << 24
        | UInt32(block[offset + 1]) << 16
        | UInt32(block[offset + 2]) << 8
        | UInt32(block[offset + 3])
      index += 1
    }
    while index < 80 {
      let expanded = words[index - 3] ^ words[index - 8]
        ^ words[index - 14] ^ words[index - 16]
      words[index] = rotateLeft(expanded, by: 1)
      index += 1
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    index = 0
    while index < 80 {
      let (function, constant): (UInt32, UInt32)
      switch index {
      case 0..<20:
        function = (b & c) | ((~b) & d)
        constant = 0x5A82_7999
      case 20..<40:
        function = b ^ c ^ d
        constant = 0x6ED9_EBA1
      case 40..<60:
        function = (b & c) | (b & d) | (c & d)
        constant = 0x8F1B_BCDC
      default:
        function = b ^ c ^ d
        constant = 0xCA62_C1D6
      }
      let rotatedA = rotateLeft(a, by: 5)
      let next = rotatedA &+ function &+ e &+ constant &+ words[index]
      e = d
      d = c
      c = rotateLeft(b, by: 30)
      b = a
      a = next
      index += 1
    }
    state[0] &+= a
    state[1] &+= b
    state[2] &+= c
    state[3] &+= d
    state[4] &+= e
  }

  package mutating func eraseSensitiveState() {
    state = [UInt32](repeating: 0, count: 5)
    pendingBytes = SIMD64<UInt8>(repeating: 0)
    pendingByteCount = 0
    totalByteCount = 0
  }
}

/// Incremental MD5 context used only for compatibility with legacy protocols.
public struct MD5Context: ~Copyable, HashContext, Sendable {
  public static let digestByteCount = 16
  private static let blockByteCount = 64
  private static let maximumInputByteCount = UInt64.max >> 3
  private static let shifts: [UInt32] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]
  private static let constants: [UInt32] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391
  ]

  private var state: [UInt32]
  private var pendingBytes: SIMD64<UInt8>
  private var pendingByteCount: Int
  private var totalByteCount: UInt64

  public init() {
    state = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476]
    pendingBytes = SIMD64<UInt8>(repeating: 0)
    pendingByteCount = 0
    totalByteCount = 0
  }

  private init(
    state: [UInt32],
    pendingBytes: SIMD64<UInt8>,
    pendingByteCount: Int,
    totalByteCount: UInt64
  ) {
    self.state = state
    self.pendingBytes = pendingBytes
    self.pendingByteCount = pendingByteCount
    self.totalByteCount = totalByteCount
  }

  public borrowing func clone() -> MD5Context {
    MD5Context(
      state: state,
      pendingBytes: pendingBytes,
      pendingByteCount: pendingByteCount,
      totalByteCount: totalByteCount
    )
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    let inputByteCount = UInt64(input.count)
    guard totalByteCount <= Self.maximumInputByteCount,
      inputByteCount <= Self.maximumInputByteCount - totalByteCount
    else {
      throw .inputTooLong(limit: Self.maximumInputByteCount)
    }
    totalByteCount += inputByteCount
    var offset = 0
    if pendingByteCount != 0 {
      let copied = Swift.min(Self.blockByteCount - pendingByteCount, input.count)
      var index = 0
      while index < copied {
        pendingBytes[pendingByteCount + index] = input[index]
        index += 1
      }
      pendingByteCount += copied
      offset += copied
      if pendingByteCount == Self.blockByteCount {
        compress(pendingBytes)
        pendingByteCount = 0
      }
    }
    while input.count - offset >= Self.blockByteCount {
      compress(input.extracting(offset..<(offset + Self.blockByteCount)))
      offset += Self.blockByteCount
    }
    let remaining = input.count - offset
    if remaining > 0 {
      var index = 0
      while index < remaining {
        pendingBytes[index] = input[offset + index]
        index += 1
      }
      pendingByteCount = remaining
    }
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    var copy = self.clone()
    let bitCount = copy.totalByteCount << 3
    copy.pendingBytes[copy.pendingByteCount] = 0x80
    copy.pendingByteCount += 1
    if copy.pendingByteCount > 56 {
      copy.zeroPendingBytes(from: copy.pendingByteCount, to: 64)
      copy.compress(copy.pendingBytes)
      copy.pendingByteCount = 0
    }
    copy.zeroPendingBytes(from: copy.pendingByteCount, to: 56)
    var index = 0
    while index < 8 {
      copy.pendingBytes[56 + index] = UInt8(truncatingIfNeeded: bitCount >> UInt64(index * 8))
      index += 1
    }
    copy.compress(copy.pendingBytes)
    index = 0
    while index < 4 {
      let word = copy.state[index]
      let offset = index * 4
      output[offset] = UInt8(truncatingIfNeeded: word)
      output[offset + 1] = UInt8(truncatingIfNeeded: word >> 8)
      output[offset + 2] = UInt8(truncatingIfNeeded: word >> 16)
      output[offset + 3] = UInt8(truncatingIfNeeded: word >> 24)
      index += 1
    }
    eraseSensitiveState()
  }

  @inline(__always)
  private mutating func zeroPendingBytes(from start: Int, to end: Int) {
    var index = start
    while index < end {
      pendingBytes[index] = 0
      index += 1
    }
  }

  private mutating func compress(_ block: Span<UInt8>) {
    block.bytes.withUnsafeBytes { bytes in
      compressBytes(bytes)
    }
  }

  private mutating func compress(_ block: SIMD64<UInt8>) {
    var block = block
    withUnsafeBytes(of: &block) { bytes in
      compressBytes(bytes)
    }
  }

  private mutating func compressBytes(_ block: UnsafeRawBufferPointer) {
    precondition(block.count == Self.blockByteCount)
    var words = [UInt32](repeating: 0, count: 16)
    var index = 0
    while index < 16 {
      let offset = index * 4
      words[index] = UInt32(block[offset])
        | UInt32(block[offset + 1]) << 8
        | UInt32(block[offset + 2]) << 16
        | UInt32(block[offset + 3]) << 24
      index += 1
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    index = 0
    while index < 64 {
      let function: UInt32
      let wordIndex: Int
      switch index {
      case 0..<16:
        function = (b & c) | ((~b) & d)
        wordIndex = index
      case 16..<32:
        function = (d & b) | ((~d) & c)
        wordIndex = (5 * index + 1) & 15
      case 32..<48:
        function = b ^ c ^ d
        wordIndex = (3 * index + 5) & 15
      default:
        function = c ^ (b | ~d)
        wordIndex = (7 * index) & 15
      }
      let sum = a &+ function &+ Self.constants[index] &+ words[wordIndex]
      let next = b &+ rotateLeft(sum, by: Self.shifts[index])
      a = d
      d = c
      c = b
      b = next
      index += 1
    }
    state[0] &+= a
    state[1] &+= b
    state[2] &+= c
    state[3] &+= d
  }

  private mutating func eraseSensitiveState() {
    state = [UInt32](repeating: 0, count: 4)
    pendingBytes = SIMD64<UInt8>(repeating: 0)
    pendingByteCount = 0
    totalByteCount = 0
  }
}

@inline(__always)
private func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
  (value << amount) | (value >> (32 - amount))
}
