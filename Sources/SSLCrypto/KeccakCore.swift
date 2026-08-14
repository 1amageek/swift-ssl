import SSLCore

/// Internal Keccak-f[1600] sponge storage shared by SHA-3 and SHAKE.
///
/// Absorption and squeezing operate on scoped spans; no pointer derived from a
/// span is retained after the operation. Callers that absorb secret material
/// must invoke `erase()` before releasing the context. The rate is always a
/// whole number of lanes, and every lane load/store uses little-endian byte
/// order from FIPS 202.
package struct KeccakCore: ~Copyable, @unchecked Sendable {
  private static let roundConstants: [UInt64] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
    0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088,
    0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B,
    0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
    0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
    0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
  ]

  private let state: UnsafeMutablePointer<UInt64>
  private var absorbOffset: Int
  private let rateByteCount: Int
  private let domainSeparator: UInt8
  private var totalByteCount: UInt64
  private var squeezeOffset: Int?

  init(rateByteCount: Int, domainSeparator: UInt8) {
    precondition(rateByteCount > 0 && rateByteCount <= 200 && rateByteCount % 8 == 0)
    state = UnsafeMutablePointer<UInt64>.allocate(capacity: 25)
    state.initialize(repeating: 0, count: 25)
    absorbOffset = 0
    self.rateByteCount = rateByteCount
    self.domainSeparator = domainSeparator
    totalByteCount = 0
    squeezeOffset = nil
  }

  private init(copying source: borrowing KeccakCore) {
    // Unsafe boundary invariants:
    // - source owns 25 initialized UInt64 lanes for the complete synchronous copy.
    // - This initializer allocates and initializes an independent 25-lane owner.
    // - No pointer escapes and no mutable alias to source is formed.
    state = UnsafeMutablePointer<UInt64>.allocate(capacity: 25)
    state.initialize(from: UnsafePointer(source.state), count: 25)
    absorbOffset = source.absorbOffset
    rateByteCount = source.rateByteCount
    domainSeparator = source.domainSeparator
    totalByteCount = source.totalByteCount
    squeezeOffset = source.squeezeOffset
  }

  borrowing func clone() -> KeccakCore {
    KeccakCore(copying: self)
  }

  mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    precondition(squeezeOffset == nil, "Keccak cannot absorb after squeezing begins")
    let byteCount = UInt64(input.count)
    guard totalByteCount <= UInt64.max - byteCount else {
      throw .inputTooLong(limit: UInt64.max)
    }
    totalByteCount += byteCount

    var offset = 0
    if absorbOffset != 0 {
      let required = rateByteCount - absorbOffset
      let copied = Swift.min(required, input.count)
      xorInput(
        input,
        sourceOffset: offset,
        destinationOffset: absorbOffset,
        byteCount: copied
      )
      absorbOffset += copied
      offset += copied
      if absorbOffset == rateByteCount {
        permute()
        absorbOffset = 0
      }
    }

    while input.count - offset >= rateByteCount {
      absorbFullBlock(input.extracting(offset..<(offset + rateByteCount)))
      offset += rateByteCount
    }

    let remainder = input.count - offset
    if remainder != 0 {
      xorInput(
        input,
        sourceOffset: offset,
        destinationOffset: 0,
        byteCount: remainder
      )
      absorbOffset = remainder
    }
  }

  mutating func update(byte: UInt8) throws(CryptoInputError) {
    precondition(squeezeOffset == nil, "Keccak cannot absorb after squeezing begins")
    guard totalByteCount < UInt64.max else {
      throw .inputTooLong(limit: UInt64.max)
    }
    totalByteCount += 1
    xorStateByte(byte, at: absorbOffset)
    absorbOffset += 1
    if absorbOffset == rateByteCount {
      permute()
      absorbOffset = 0
    }
  }

  mutating func finalize(into output: inout MutableSpan<UInt8>) {
    squeeze(into: &output)
  }

  /// Continues squeezing the same XOF stream into caller-owned storage.
  ///
  /// This is intentionally internal: public SHAKE contexts remain consuming
  /// one-shot finalizers, while rejection samplers can request bounded chunks
  /// without recomputing or materializing an arbitrarily large output.
  mutating func squeeze(into output: inout MutableSpan<UInt8>) {
    if squeezeOffset == nil {
      xorStateByte(domainSeparator, at: absorbOffset)
      xorStateByte(0x80, at: rateByteCount - 1)
      permute()
      absorbOffset = 0
      squeezeOffset = 0
    }

    var outputOffset = 0
    while outputOffset < output.count {
      guard var stateOffset = squeezeOffset else {
        preconditionFailure("Keccak squeeze state was not initialized")
      }
      if stateOffset == rateByteCount {
        permute()
        stateOffset = 0
      }

      let available = Swift.min(
        rateByteCount - stateOffset,
        output.count - outputOffset
      )
      var index = 0
      while index < available {
        let byteIndex = stateOffset + index
        let laneIndex = byteIndex / 8
        let shift = UInt64((byteIndex % 8) * 8)
        output[outputOffset + index] = UInt8(
          truncatingIfNeeded: state[laneIndex] >> shift
        )
        index += 1
      }
      outputOffset += available
      squeezeOffset = stateOffset + available
    }
  }

  mutating func erase() {
    // Unsafe boundary invariants:
    // - state owns 25 initialized UInt64 lanes and is exclusively borrowed.
    // - The state contains both permuted lanes and any partial absorbed block.
    // - No pointer escapes, and all secret-bearing counters are reset afterward.
    SecureWipe.eraseUInt64Words(
      UnsafeMutableRawPointer(state),
      wordCount: 25
    )
    absorbOffset = 0
    totalByteCount = 0
    squeezeOffset = nil
  }

  private mutating func absorbFullBlock(_ block: Span<UInt8>) {
    precondition(block.count == rateByteCount)
    // Unsafe boundary invariants:
    // - block contains exactly rateByteCount readable bytes and remains alive
    //   throughout this synchronous closure.
    // - loadUnaligned never requires input alignment or binds input memory.
    // - rateByteCount is a multiple of eight, every load stays in bounds, and
    //   the uniquely owned state has 25 initialized UInt64 lanes.
    block.bytes.withUnsafeBytes { bytes in
      var laneIndex = 0
      while laneIndex < rateByteCount / 8 {
        let word = bytes.loadUnaligned(
          fromByteOffset: laneIndex * 8,
          as: UInt64.self
        )
        xorLane(at: laneIndex, with: UInt64(littleEndian: word))
        laneIndex += 1
      }
    }
    permute()
  }

  @inline(__always)
  private mutating func xorInput(
    _ input: Span<UInt8>,
    sourceOffset: Int,
    destinationOffset: Int,
    byteCount: Int
  ) {
    precondition(sourceOffset >= 0 && sourceOffset + byteCount <= input.count)
    precondition(destinationOffset >= 0)
    precondition(destinationOffset + byteCount <= rateByteCount)
    var index = 0
    while index < byteCount {
      xorStateByte(input[sourceOffset + index], at: destinationOffset + index)
      index += 1
    }
  }

  @inline(__always)
  private mutating func xorStateByte(_ byte: UInt8, at index: Int) {
    precondition(index >= 0 && index < rateByteCount)
    let laneIndex = index / 8
    let shift = UInt64((index & 7) * 8)
    xorLane(at: laneIndex, with: UInt64(byte) << shift)
  }

  /// Performs an explicit load/store instead of a pointer-subscript compound
  /// assignment. Swift 6.4's TSan instrumentation cannot lower the implicit
  /// inout access formed by that compound assignment on this noncopyable owner.
  @inline(__always)
  private func xorLane(at index: Int, with value: UInt64) {
    precondition(index >= 0 && index < 25)
    state[index] = state[index] ^ value
  }

  @inline(__always)
  private mutating func permute() {
    // Unsafe boundary invariants:
    // - This noncopyable value uniquely owns exactly 25 initialized UInt64 lanes.
    // - All accessed indices are in 0..<25.
    // - UInt64 alignment and initialization are preserved and mutation is exclusive.
    var round = 0
    while round < 24 {
      let c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20]
      let c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21]
      let c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22]
      let c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23]
      let c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24]
      let d0 = c4 ^ c1.rotatingLeft(by: 1)
      let d1 = c0 ^ c2.rotatingLeft(by: 1)
      let d2 = c1 ^ c3.rotatingLeft(by: 1)
      let d3 = c2 ^ c4.rotatingLeft(by: 1)
      let d4 = c3 ^ c0.rotatingLeft(by: 1)

      xorLane(at: 0, with: d0)
      xorLane(at: 5, with: d0)
      xorLane(at: 10, with: d0)
      xorLane(at: 15, with: d0)
      xorLane(at: 20, with: d0)
      xorLane(at: 1, with: d1)
      xorLane(at: 6, with: d1)
      xorLane(at: 11, with: d1)
      xorLane(at: 16, with: d1)
      xorLane(at: 21, with: d1)
      xorLane(at: 2, with: d2)
      xorLane(at: 7, with: d2)
      xorLane(at: 12, with: d2)
      xorLane(at: 17, with: d2)
      xorLane(at: 22, with: d2)
      xorLane(at: 3, with: d3)
      xorLane(at: 8, with: d3)
      xorLane(at: 13, with: d3)
      xorLane(at: 18, with: d3)
      xorLane(at: 23, with: d3)
      xorLane(at: 4, with: d4)
      xorLane(at: 9, with: d4)
      xorLane(at: 14, with: d4)
      xorLane(at: 19, with: d4)
      xorLane(at: 24, with: d4)

      let b0 = state[0]
      let b10 = state[1].rotatingLeft(by: 1)
      let b20 = state[2].rotatingLeft(by: 62)
      let b5 = state[3].rotatingLeft(by: 28)
      let b15 = state[4].rotatingLeft(by: 27)
      let b16 = state[5].rotatingLeft(by: 36)
      let b1 = state[6].rotatingLeft(by: 44)
      let b11 = state[7].rotatingLeft(by: 6)
      let b21 = state[8].rotatingLeft(by: 55)
      let b6 = state[9].rotatingLeft(by: 20)
      let b7 = state[10].rotatingLeft(by: 3)
      let b17 = state[11].rotatingLeft(by: 10)
      let b2 = state[12].rotatingLeft(by: 43)
      let b12 = state[13].rotatingLeft(by: 25)
      let b22 = state[14].rotatingLeft(by: 39)
      let b23 = state[15].rotatingLeft(by: 41)
      let b8 = state[16].rotatingLeft(by: 45)
      let b18 = state[17].rotatingLeft(by: 15)
      let b3 = state[18].rotatingLeft(by: 21)
      let b13 = state[19].rotatingLeft(by: 8)
      let b14 = state[20].rotatingLeft(by: 18)
      let b24 = state[21].rotatingLeft(by: 2)
      let b9 = state[22].rotatingLeft(by: 61)
      let b19 = state[23].rotatingLeft(by: 56)
      let b4 = state[24].rotatingLeft(by: 14)

      state[0] = b0 ^ ((~b1) & b2)
      state[1] = b1 ^ ((~b2) & b3)
      state[2] = b2 ^ ((~b3) & b4)
      state[3] = b3 ^ ((~b4) & b0)
      state[4] = b4 ^ ((~b0) & b1)
      state[5] = b5 ^ ((~b6) & b7)
      state[6] = b6 ^ ((~b7) & b8)
      state[7] = b7 ^ ((~b8) & b9)
      state[8] = b8 ^ ((~b9) & b5)
      state[9] = b9 ^ ((~b5) & b6)
      state[10] = b10 ^ ((~b11) & b12)
      state[11] = b11 ^ ((~b12) & b13)
      state[12] = b12 ^ ((~b13) & b14)
      state[13] = b13 ^ ((~b14) & b10)
      state[14] = b14 ^ ((~b10) & b11)
      state[15] = b15 ^ ((~b16) & b17)
      state[16] = b16 ^ ((~b17) & b18)
      state[17] = b17 ^ ((~b18) & b19)
      state[18] = b18 ^ ((~b19) & b15)
      state[19] = b19 ^ ((~b15) & b16)
      state[20] = b20 ^ ((~b21) & b22)
      state[21] = b21 ^ ((~b22) & b23)
      state[22] = b22 ^ ((~b23) & b24)
      state[23] = b23 ^ ((~b24) & b20)
      state[24] = b24 ^ ((~b20) & b21)

      xorLane(at: 0, with: Self.roundConstants[round])
      round += 1
    }
  }

  deinit {
    // The state also owns any partial absorbed block, so one volatile wipe
    // covers every input byte retained by this context before deallocation.
    SecureWipe.eraseUInt64Words(
      UnsafeMutableRawPointer(state),
      wordCount: 25
    )
    state.deinitialize(count: 25)
    state.deallocate()
  }
}

extension UInt64 {
  @inline(__always)
  fileprivate func rotatingLeft(by amount: Int) -> UInt64 {
    let shift = UInt64(amount)
    return (self << shift) | (self >> (64 - shift))
  }
}
