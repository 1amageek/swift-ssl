import SSLCore

/// Incremental SHA-512 context. The scalar compressor is shared by SHA-512
/// and the SHA-384 truncated variant; target-specific acceleration is a later
/// backend decision and does not change this state contract.
public struct SHA512Context: ~Copyable, HashContext, HMACSHA2Context, Sendable {
  public static let digestByteCount = 64
  fileprivate static let blockByteCount = 128
  fileprivate static let maximumInputByteCount = UInt64.max >> 3

  private var state: [UInt64]
  private var pendingBytes: [UInt8]
  private var pendingByteCount: Int
  private var totalByteCount: UInt64

  public init() {
    self.init(initialState: Self.sha512InitialState)
  }

  fileprivate init(initialState: [UInt64]) {
    state = initialState
    pendingBytes = [UInt8](repeating: 0, count: Self.blockByteCount)
    pendingByteCount = 0
    totalByteCount = 0
  }

  private init(
    state: [UInt64], pendingBytes: [UInt8], pendingByteCount: Int,
    totalByteCount: UInt64
  ) {
    self.state = state
    self.pendingBytes = pendingBytes
    self.pendingByteCount = pendingByteCount
    self.totalByteCount = totalByteCount
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    let inputCount = UInt64(input.count)
    guard totalByteCount <= Self.maximumInputByteCount,
      inputCount <= Self.maximumInputByteCount - totalByteCount
    else {
      throw .inputTooLong(limit: Self.maximumInputByteCount)
    }
    totalByteCount += inputCount
    var offset = 0
    if pendingByteCount > 0 {
      let count = min(Self.blockByteCount - pendingByteCount, input.count)
      copy(input, from: offset, count: count, into: pendingByteCount)
      pendingByteCount += count
      offset += count
      if pendingByteCount == Self.blockByteCount {
        compressPending()
        pendingByteCount = 0
      }
    }
    while offset + Self.blockByteCount <= input.count {
      let block = input.extracting(offset..<(offset + Self.blockByteCount))
      compress(block)
      offset += Self.blockByteCount
    }
    if offset < input.count {
      copy(input, from: offset, count: input.count - offset, into: 0)
      pendingByteCount = input.count - offset
    }
  }

  public borrowing func clone() -> SHA512Context {
    SHA512Context(
      state: state, pendingBytes: pendingBytes,
      pendingByteCount: pendingByteCount, totalByteCount: totalByteCount
    )
  }

  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try finalizeInPlace(into: &output)
  }

  package mutating func finalizeInPlace(into output: inout MutableSpan<UInt8>)
    throws(CryptoInputError)
  {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    pendingBytes[pendingByteCount] = 0x80
    pendingByteCount += 1
    if pendingByteCount > 112 {
      zero(from: pendingByteCount, to: Self.blockByteCount)
      compressPending()
      pendingByteCount = 0
    }
    zero(from: pendingByteCount, to: 112)
    var index = 0
    while index < 8 {
      pendingBytes[112 + index] = 0
      index += 1
      pendingBytes[120 + index - 1] = UInt8(
        truncatingIfNeeded: (totalByteCount << 3) >> UInt64((7 - index + 1) * 8))
    }
    compressPending()
    index = 0
    while index < 8 {
      Self.writeBigEndian(state[index], into: &output, offset: index * 8)
      index += 1
    }
  }

  package mutating func eraseSensitiveState() {
    state.withUnsafeMutableBufferPointer { buffer in
      if let baseAddress = buffer.baseAddress {
        SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count * 8)
      }
    }
    pendingBytes.withUnsafeMutableBufferPointer { buffer in
      if let baseAddress = buffer.baseAddress {
        SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
      }
    }
    pendingByteCount = 0
    totalByteCount = 0
  }

  private mutating func copy(
    _ input: Span<UInt8>, from sourceOffset: Int, count: Int, into destinationOffset: Int
  ) {
    guard count > 0 else { return }
    input.withUnsafeBytes { source in
      pendingBytes.withUnsafeMutableBufferPointer { destination in
        destination.baseAddress!.advanced(by: destinationOffset)
          .update(
            from: source.baseAddress!.assumingMemoryBound(to: UInt8.self).advanced(
              by: sourceOffset),
            count: count
          )
      }
    }
  }

  private mutating func zero(from start: Int, to end: Int) {
    guard start < end else { return }
    while pendingBytes.count > 0 && start < end {
      pendingBytes[start] = 0
      if start + 1 >= end { break }
      pendingBytes.replaceSubrange(
        (start + 1)..<end, with: repeatElement(UInt8(0), count: end - start - 1))
      break
    }
  }

  private mutating func compressPending() {
    pendingBytes.withUnsafeBufferPointer { buffer in
      compress(Span(_unsafeElements: buffer))
    }
  }

  private mutating func compress(_ block: Span<UInt8>) {
    var schedule = [UInt64](repeating: 0, count: 80)
    var index = 0
    while index < 16 {
      var word: UInt64 = 0
      var byte = 0
      while byte < 8 {
        word = (word << 8) | UInt64(block[index * 8 + byte])
        byte += 1
      }
      schedule[index] = word
      index += 1
    }
    while index < 80 {
      let x = schedule[index - 15]
      let y = schedule[index - 2]
      let s0 = x.rotatedRight(by: 1) ^ x.rotatedRight(by: 8) ^ (x >> 7)
      let s1 = y.rotatedRight(by: 19) ^ y.rotatedRight(by: 61) ^ (y >> 6)
      schedule[index] = schedule[index - 16] &+ s0 &+ schedule[index - 7] &+ s1
      index += 1
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    index = 0
    while index < 80 {
      let s1 = e.rotatedRight(by: 14) ^ e.rotatedRight(by: 18) ^ e.rotatedRight(by: 41)
      let ch = (e & f) ^ (~e & g)
      let temp1 = h &+ s1 &+ ch &+ Self.roundConstants[index] &+ schedule[index]
      let s0 = a.rotatedRight(by: 28) ^ a.rotatedRight(by: 34) ^ a.rotatedRight(by: 39)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 &+ maj
      h = g
      g = f
      f = e
      e = d &+ temp1
      d = c
      c = b
      b = a
      a = temp1 &+ temp2
      index += 1
    }
    state[0] &+= a
    state[1] &+= b
    state[2] &+= c
    state[3] &+= d
    state[4] &+= e
    state[5] &+= f
    state[6] &+= g
    state[7] &+= h
    // Unsafe boundary invariants:
    // - `schedule` owns 80 initialized UInt64 words and is exclusively mutable
    //   for this synchronous closure.
    // - The byte count comes from the buffer itself, so it covers exactly the
    //   initialized allocation without relying on an unchecked multiplication.
    // - The raw pointer remains inside the closure and never escapes its borrow.
    schedule.withUnsafeMutableBytes { bytes in
      guard let baseAddress = bytes.baseAddress else { return }
      SecureWipe.erase(baseAddress, byteCount: bytes.count)
    }
  }

  private static func writeBigEndian(
    _ value: UInt64, into output: inout MutableSpan<UInt8>, offset: Int
  ) {
    var index = 0
    while index < 8 {
      output[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64((7 - index) * 8))
      index += 1
    }
  }

  private static let sha512InitialState: [UInt64] = [
    0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
  ]
  fileprivate static let sha384InitialState: [UInt64] = [
    0xcbbb_9d5d_c105_9ed8, 0x629a_292a_367c_d507, 0x9159_015a_3070_dd17, 0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31, 0x8eb4_4a87_6858_1511, 0xdb0c_2e0d_64f9_8fa7, 0x47b5_481d_befa_4fa4,
  ]
  private static let roundConstants: [UInt64] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
  ]
}

extension UInt64 {
  @inline(__always) fileprivate func rotatedRight(by amount: UInt64) -> UInt64 {
    (self >> amount) | (self << (64 - amount))
  }
}

public struct SHA384Context: ~Copyable, HashContext, HMACSHA2Context, Sendable {
  public static let digestByteCount = 48
  private var inner: SHA512Context

  public init() { inner = SHA512Context(initialState: SHA512Context.sha384InitialState) }
  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try inner.update(input)
  }
  public borrowing func clone() -> SHA384Context {
    var result = SHA384Context()
    result.inner = inner.clone()
    return result
  }
  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try finalizeInPlace(into: &output)
  }
  package mutating func finalizeInPlace(into output: inout MutableSpan<UInt8>)
    throws(CryptoInputError)
  {
    guard output.count == Self.digestByteCount else {
      throw .invalidOutputLength(expected: Self.digestByteCount, actual: output.count)
    }
    // The temporary owner is allocated for this synchronous call, handed
    // to MutableSpan only within the finalize call, wiped, and deallocated
    // exactly once before returning. Its pointer never escapes.
    let temporary = UnsafeMutablePointer<UInt8>.allocate(capacity: SHA512Context.digestByteCount)
    temporary.initialize(repeating: 0, count: SHA512Context.digestByteCount)
    defer {
      SecureWipe.erase(temporary, byteCount: SHA512Context.digestByteCount)
      temporary.deinitialize(count: SHA512Context.digestByteCount)
      temporary.deallocate()
    }
    var fullSpan = MutableSpan(_unsafeStart: temporary, count: SHA512Context.digestByteCount)
    try inner.finalizeInPlace(into: &fullSpan)
    var index = 0
    while index < Self.digestByteCount {
      output[index] = temporary[index]
      index += 1
    }
  }
  package mutating func eraseSensitiveState() { inner.eraseSensitiveState() }
}
