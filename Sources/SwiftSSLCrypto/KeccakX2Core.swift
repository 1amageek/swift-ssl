import SwiftSSLCore

#if os(macOS) && arch(arm64) && canImport(simd)
  import simd
#endif

/// Two parallel SHAKE states for ML-KEM matrix and noise expansion.
struct KeccakX2Core: ~Copyable {
  enum Sensitivity: Equatable {
    case publicData
    case secret
  }

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

  private let state: UnsafeMutablePointer<SIMD2<UInt64>>
  private let sensitivity: Sensitivity

  init(sensitivity: Sensitivity) {
    state = UnsafeMutablePointer<SIMD2<UInt64>>.allocate(capacity: 25)
    state.initialize(repeating: SIMD2(repeating: 0), count: 25)
    self.sensitivity = sensitivity
  }

  init(
    seed: Span<UInt8>,
    firstSuffix: (UInt8, UInt8),
    secondSuffix: (UInt8, UInt8)
  ) {
    self.init(sensitivity: .publicData)
    reset(seed: seed, firstSuffix: firstSuffix, secondSuffix: secondSuffix)
  }

  mutating func reset(
    seed: Span<UInt8>,
    firstSuffix: (UInt8, UInt8),
    secondSuffix: (UInt8, UInt8)
  ) {
    precondition(seed.count == 32 && sensitivity == .publicData)
    resetState()

    seed.bytes.withUnsafeBytes { bytes in
      // The exact 32-byte seed remains borrowed for this synchronous scope.
      // Four unaligned loads cover it completely without binding its memory.
      var lane = 0
      while lane < 4 {
        let word = bytes.loadUnaligned(
          fromByteOffset: lane * MemoryLayout<UInt64>.stride,
          as: UInt64.self
        )
        state[lane] = SIMD2(repeating: UInt64(littleEndian: word))
        lane += 1
      }
    }

    state[4] = SIMD2(
      Self.suffixLane(firstSuffix),
      Self.suffixLane(secondSuffix)
    )
    state[20] = SIMD2(repeating: UInt64(0x80) << 56)
    permute()
  }

  init(
    secretSeed: Span<UInt8>,
    firstNonce: UInt8,
    secondNonce: UInt8
  ) {
    self.init(sensitivity: .secret)
    reset(secretSeed: secretSeed, firstNonce: firstNonce, secondNonce: secondNonce)
  }

  mutating func reset(
    secretSeed: Span<UInt8>,
    firstNonce: UInt8,
    secondNonce: UInt8
  ) {
    precondition(secretSeed.count == 32 && sensitivity == .secret)
    resetState()

    secretSeed.bytes.withUnsafeBytes { bytes in
      // The exact 32-byte secret seed remains borrowed and initialized for all
      // four bounded unaligned loads. No pointer is retained or rebound.
      var lane = 0
      while lane < 4 {
        let word = bytes.loadUnaligned(
          fromByteOffset: lane * MemoryLayout<UInt64>.stride,
          as: UInt64.self
        )
        state[lane] = SIMD2(repeating: UInt64(littleEndian: word))
        lane += 1
      }
    }

    state[4] = SIMD2(
      Self.nonceLane(firstNonce),
      Self.nonceLane(secondNonce)
    )
    state[16] = SIMD2(repeating: UInt64(0x80) << 56)
    permute()
  }

  init(
    mlDSASecretSeed: Span<UInt8>,
    firstNonce: UInt16,
    secondNonce: UInt16
  ) {
    self.init(sensitivity: .secret)
    reset(
      mlDSASecretSeed: mlDSASecretSeed,
      firstNonce: firstNonce,
      secondNonce: secondNonce
    )
  }

  mutating func reset(
    mlDSASecretSeed: Span<UInt8>,
    firstNonce: UInt16,
    secondNonce: UInt16
  ) {
    precondition(mlDSASecretSeed.count == 64 && sensitivity == .secret)
    resetState()

    mlDSASecretSeed.bytes.withUnsafeBytes { bytes in
      // The exact 64-byte secret seed remains borrowed and initialized for all
      // eight bounded unaligned loads. No pointer is retained or rebound.
      var lane = 0
      while lane < 8 {
        let word = bytes.loadUnaligned(
          fromByteOffset: lane * MemoryLayout<UInt64>.stride,
          as: UInt64.self
        )
        state[lane] = SIMD2(repeating: UInt64(littleEndian: word))
        lane += 1
      }
    }

    state[8] = SIMD2(
      Self.mlDSANonceLane(firstNonce),
      Self.mlDSANonceLane(secondNonce)
    )
    state[16] = SIMD2(repeating: UInt64(0x80) << 56)
    permute()
  }

  mutating func sha3_512(
    first: Span<UInt8>,
    second: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(
      first.count == 32 && second.count == 32 && output.count == 64
        && sensitivity == .secret
    )
    resetState()

    var lane = 0
    while lane < 4 {
      state[lane] = SIMD2(repeating: Self.loadWord(first, lane: lane))
      state[lane + 4] = SIMD2(repeating: Self.loadWord(second, lane: lane))
      lane += 1
    }
    state[8] = SIMD2(repeating: UInt64(0x06) | (UInt64(0x80) << 56))
    permute()
    writeFirstStream(byteCount: 64, into: &output)
  }

  mutating func sha3_512(
    first: Span<UInt8>,
    suffix: UInt8,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(first.count == 32 && output.count == 64 && sensitivity == .secret)
    resetState()

    var lane = 0
    while lane < 4 {
      state[lane] = SIMD2(repeating: Self.loadWord(first, lane: lane))
      lane += 1
    }
    state[4] = SIMD2(repeating: UInt64(suffix) | (UInt64(0x06) << 8))
    state[8] = SIMD2(repeating: UInt64(0x80) << 56)
    permute()
    writeFirstStream(byteCount: 64, into: &output)
  }

  mutating func sha3_256(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(output.count == 32 && sensitivity == .publicData)
    resetState()

    let rateByteCount = 136
    var inputOffset = 0
    input.bytes.withUnsafeBytes { bytes in
      // Unsafe boundary invariants:
      // - `bytes` borrows the initialized input storage only for this closure.
      // - Every unaligned load is bounded by a complete 136-byte SHA3 rate block
      //   or by the remaining complete words in the final partial block.
      // - The uniquely owned state remains initialized and no pointer escapes.
      while bytes.count - inputOffset >= rateByteCount {
        var laneIndex = 0
        while laneIndex < rateByteCount / 8 {
          let word = bytes.loadUnaligned(
            fromByteOffset: inputOffset + laneIndex * 8,
            as: UInt64.self
          )
          state[laneIndex] ^= SIMD2(repeating: UInt64(littleEndian: word))
          laneIndex += 1
        }
        permute()
        inputOffset += rateByteCount
      }

      var remainderOffset = 0
      let remainderByteCount = bytes.count - inputOffset
      while remainderByteCount - remainderOffset >= 8 {
        let word = bytes.loadUnaligned(
          fromByteOffset: inputOffset + remainderOffset,
          as: UInt64.self
        )
        state[remainderOffset >> 3] ^=
          SIMD2(repeating: UInt64(littleEndian: word))
        remainderOffset += 8
      }
      while remainderOffset < remainderByteCount {
        xorSameByte(
          bytes[inputOffset + remainderOffset],
          at: remainderOffset
        )
        remainderOffset += 1
      }
    }

    let paddingOffset = input.count - inputOffset
    xorSameByte(0x06, at: paddingOffset)
    xorSameByte(0x80, at: rateByteCount - 1)
    permute()
    writeFirstStream(byteCount: 32, into: &output)
  }

  mutating func shake256(
    first: Span<UInt8>,
    second: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(first.count == 32 && output.count == 32 && sensitivity == .secret)
    resetState()

    let rateByteCount = 136
    var rateOffset = 0
    absorbSameInput(
      first,
      rateByteCount: rateByteCount,
      rateOffset: &rateOffset
    )
    absorbSameInput(
      second,
      rateByteCount: rateByteCount,
      rateOffset: &rateOffset
    )
    xorSameByte(0x1F, at: rateOffset)
    xorSameByte(0x80, at: rateByteCount - 1)
    permute()
    writeFirstStream(byteCount: 32, into: &output)
  }

  private mutating func absorbSameInput(
    _ input: Span<UInt8>,
    rateByteCount: Int,
    rateOffset: inout Int
  ) {
    precondition(
      rateByteCount > 0 && rateByteCount <= 200
        && rateByteCount.isMultiple(of: 8)
        && rateOffset >= 0 && rateOffset < rateByteCount
    )
    var inputOffset = 0
    input.bytes.withUnsafeBytes { bytes in
      // Unsafe boundary invariants:
      // - `bytes` borrows initialized input storage only for this closure and
      //   no pointer derived from it escapes.
      // - Every unaligned word load is guarded by eight remaining input bytes;
      //   the rate offset is word aligned and remains within the 136-byte rate.
      // - The uniquely owned state contains 25 initialized lanes and is never
      //   rebound or aliased while this exclusive mutating borrow is active.
      while inputOffset < bytes.count && !rateOffset.isMultiple(of: 8) {
        xorSameByte(bytes[inputOffset], at: rateOffset)
        inputOffset += 1
        rateOffset += 1
        if rateOffset == rateByteCount {
          permute()
          rateOffset = 0
        }
      }

      while bytes.count - inputOffset >= 8 {
        let word = bytes.loadUnaligned(fromByteOffset: inputOffset, as: UInt64.self)
        state[rateOffset >> 3] ^= SIMD2(repeating: UInt64(littleEndian: word))
        inputOffset += 8
        rateOffset += 8
        if rateOffset == rateByteCount {
          permute()
          rateOffset = 0
        }
      }

      while inputOffset < bytes.count {
        xorSameByte(bytes[inputOffset], at: rateOffset)
        inputOffset += 1
        rateOffset += 1
        if rateOffset == rateByteCount {
          permute()
          rateOffset = 0
        }
      }
    }
  }

  @inline(__always)
  private mutating func resetState() {
    // All lanes are overwritten before reuse. This both establishes the
    // all-zero Keccak initial state and removes prior secret material without
    // allocating another owner; final destruction still uses a volatile wipe.
    state.update(repeating: SIMD2(repeating: 0), count: 25)
  }

  @inline(__always)
  private static func loadWord(_ input: Span<UInt8>, lane: Int) -> UInt64 {
    precondition(input.count == 32 && lane >= 0 && lane < 4)
    let offset = lane * 8
    var word: UInt64 = 0
    var byte = 0
    while byte < 8 {
      word |= UInt64(input[offset + byte]) << UInt64(byte * 8)
      byte += 1
    }
    return word
  }

  @inline(__always)
  private mutating func xorSameByte(_ byte: UInt8, at byteIndex: Int) {
    precondition(byteIndex >= 0 && byteIndex < 200)
    let value = UInt64(byte) << UInt64((byteIndex & 7) * 8)
    state[byteIndex >> 3] ^= SIMD2(repeating: value)
  }

  @inline(__always)
  private borrowing func writeFirstStream(
    byteCount: Int,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(byteCount >= 0 && byteCount <= 200 && output.count == byteCount)
    var byteIndex = 0
    while byteIndex < byteCount {
      let word = state[byteIndex >> 3][0]
      output[byteIndex] = UInt8(
        truncatingIfNeeded: word >> UInt64((byteIndex & 7) * 8)
      )
      byteIndex += 1
    }
  }

  mutating func sampleNTT(
    first: inout MutableSpan<MLKEMArithmetic.Coefficient>,
    second: inout MutableSpan<MLKEMArithmetic.Coefficient>
  ) {
    precondition(first.count == 256 && second.count == 256)
    // Unsafe boundary invariants:
    // - The two validated spans each contain exactly 256 initialized coefficients.
    // - MLKEMPolynomialStorage lends disjoint polynomial ranges to this function.
    // - Candidate counters never exceed 256 and every pointer remains scoped to
    //   these synchronous exclusive borrows.
    first.withUnsafeMutableBufferPointer { firstBuffer in
      second.withUnsafeMutableBufferPointer { secondBuffer in
        sampleNTT(
          first: firstBuffer.baseAddress.unsafelyUnwrapped,
          second: secondBuffer.baseAddress.unsafelyUnwrapped
        )
      }
    }
  }

  mutating func sampleNTT(
    into first: inout MutableSpan<MLKEMArithmetic.Coefficient>
  ) {
    precondition(first.count == 256)
    // Unsafe boundary invariants:
    // - The validated span contains exactly 256 initialized coefficients.
    // - Only stream zero is materialized; stream one is an identical padding
    //   stream used to retain the faster two-way permutation for odd tails.
    // - The pointer remains scoped to this synchronous exclusive borrow.
    first.withUnsafeMutableBufferPointer { firstBuffer in
      let firstPointer = firstBuffer.baseAddress.unsafelyUnwrapped
      var firstCount = 0
      while firstCount < 256 {
        var laneIndex = 0
        while laneIndex < 21 {
          Self.append24ByteCandidates(
            state[laneIndex][0],
            state[laneIndex + 1][0],
            state[laneIndex + 2][0],
            into: firstPointer,
            count: &firstCount
          )
          laneIndex += 3
        }
        if firstCount < 256 {
          permute()
        }
      }
    }
  }

  private mutating func sampleNTT(
    first: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>,
    second: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>
  ) {
    var firstCount = 0
    var secondCount = 0

    while firstCount < 256 || secondCount < 256 {
      var laneIndex = 0
      while laneIndex < 21 && (firstCount < 256 || secondCount < 256) {
        let firstLane = state[laneIndex]
        let secondLane = state[laneIndex + 1]
        let thirdLane = state[laneIndex + 2]
        Self.append24ByteCandidates(
          firstLane[0],
          secondLane[0],
          thirdLane[0],
          into: first,
          count: &firstCount
        )
        Self.append24ByteCandidates(
          firstLane[1],
          secondLane[1],
          thirdLane[1],
          into: second,
          count: &secondCount
        )
        laneIndex += 3
      }
      if firstCount < 256 || secondCount < 256 {
        permute()
      }
    }
  }

  mutating func sampleCBDEta2(
    first: inout MutableSpan<MLKEMArithmetic.Coefficient>,
    second: inout MutableSpan<MLKEMArithmetic.Coefficient>
  ) {
    precondition(first.count == 256 && second.count == 256)
    // The storage and lifetime invariants match sampleNTT. Each byte produces
    // exactly two coefficients, so byteIndex 0..<128 maps to 0..<256.
    first.withUnsafeMutableBufferPointer { firstBuffer in
      second.withUnsafeMutableBufferPointer { secondBuffer in
        let firstPointer = firstBuffer.baseAddress.unsafelyUnwrapped
        let secondPointer = secondBuffer.baseAddress.unsafelyUnwrapped
        var laneIndex = 0
        while laneIndex < 16 {
          let words = state[laneIndex]
          let coefficientIndex = laneIndex * 16
          Self.storeCBDEta2(
            words[0],
            coefficientIndex: coefficientIndex,
            into: firstPointer
          )
          Self.storeCBDEta2(
            words[1],
            coefficientIndex: coefficientIndex,
            into: secondPointer
          )
          laneIndex += 1
        }
      }
    }
  }

  mutating func squeezeMLDSAMasks(
    first: UnsafeMutablePointer<UInt8>,
    second: UnsafeMutablePointer<UInt8>,
    byteCount: Int
  ) {
    precondition(byteCount >= 0 && sensitivity == .secret)
    // Unsafe boundary invariants:
    // - both outputs own byteCount initialized bytes and are disjoint;
    // - every store is guarded by byteCount and the fixed 136-byte rate;
    // - neither pointer is retained or allowed to escape this synchronous call;
    // - the owner wipes both outputs after their final decode.
    var outputOffset = 0
    while outputOffset < byteCount {
      let blockByteCount = min(136, byteCount - outputOffset)
      var byteIndex = 0
      while byteIndex < blockByteCount {
        let words = state[byteIndex >> 3]
        let shift = UInt64((byteIndex & 7) * 8)
        first[outputOffset + byteIndex] = UInt8(
          truncatingIfNeeded: words[0] >> shift
        )
        second[outputOffset + byteIndex] = UInt8(
          truncatingIfNeeded: words[1] >> shift
        )
        byteIndex += 1
      }
      outputOffset += blockByteCount
      if outputOffset < byteCount {
        permute()
      }
    }
  }

  mutating func sampleCBDEta2(
    into first: inout MutableSpan<MLKEMArithmetic.Coefficient>
  ) {
    precondition(first.count == 256)
    // The single-output tail follows the same scoped ownership contract as
    // the two-output method and does not materialize the padding stream.
    first.withUnsafeMutableBufferPointer { firstBuffer in
      let firstPointer = firstBuffer.baseAddress.unsafelyUnwrapped
      var laneIndex = 0
      while laneIndex < 16 {
        Self.storeCBDEta2(
          state[laneIndex][0],
          coefficientIndex: laneIndex * 16,
          into: firstPointer
        )
        laneIndex += 1
      }
    }
  }

  mutating func sampleMLDSAMatrix(
    first: UnsafeMutablePointer<UInt32>,
    second: UnsafeMutablePointer<UInt32>
  ) {
    precondition(sensitivity == .publicData)
    // Unsafe boundary invariants:
    // - both destinations own 256 initialized UInt32 values and are disjoint;
    // - accepted counters are checked before every store and never exceed 256;
    // - the pointers remain scoped to this synchronous call and never escape;
    // - the public SHAKE state is uniquely owned for every permutation.
    var firstCount = 0
    var secondCount = 0
    while firstCount < 256 || secondCount < 256 {
      var laneIndex = 0
      while laneIndex < 21 {
        let firstLane = state[laneIndex]
        let secondLane = state[laneIndex + 1]
        let thirdLane = state[laneIndex + 2]
        Self.appendMLDSAMatrixCandidates(
          firstLane[0],
          secondLane[0],
          thirdLane[0],
          into: first,
          count: &firstCount
        )
        Self.appendMLDSAMatrixCandidates(
          firstLane[1],
          secondLane[1],
          thirdLane[1],
          into: second,
          count: &secondCount
        )
        laneIndex += 3
      }
      if firstCount < 256 || secondCount < 256 {
        permute()
      }
    }
  }

  mutating func sampleMLDSAShort(
    first: UnsafeMutablePointer<UInt32>,
    second: UnsafeMutablePointer<UInt32>,
    eta: UInt32
  ) {
    precondition(sensitivity == .secret && (eta == 2 || eta == 4))
    // Unsafe boundary invariants:
    // - both destinations own 256 initialized UInt32 values and are disjoint;
    // - accepted counters are checked before every store and never exceed 256;
    // - no pointer crosses the synchronous borrow or a Sendable boundary;
    // - reset and deinit erase the uniquely owned secret SHAKE state.
    if eta == 4 {
      sampleMLDSAShortEta4(first: first, second: second)
    } else {
      sampleMLDSAShortEta2(first: first, second: second)
    }
  }

  private mutating func sampleMLDSAShortEta4(
    first: UnsafeMutablePointer<UInt32>,
    second: UnsafeMutablePointer<UInt32>
  ) {
    var firstCount = 0
    var secondCount = 0
    while firstCount < 256 || secondCount < 256 {
      var laneIndex = 0
      while laneIndex < 17 && (firstCount < 256 || secondCount < 256) {
        let words = state[laneIndex]
        var byteIndex = 0
        while byteIndex < 8 && (firstCount < 256 || secondCount < 256) {
          let shift = UInt64(byteIndex * 8)
          Self.appendMLDSAShortByteEta4(
            UInt8(truncatingIfNeeded: words[0] >> shift),
            into: first,
            count: &firstCount
          )
          Self.appendMLDSAShortByteEta4(
            UInt8(truncatingIfNeeded: words[1] >> shift),
            into: second,
            count: &secondCount
          )
          byteIndex += 1
        }
        laneIndex += 1
      }
      if firstCount < 256 || secondCount < 256 {
        permute()
      }
    }
  }

  private mutating func sampleMLDSAShortEta2(
    first: UnsafeMutablePointer<UInt32>,
    second: UnsafeMutablePointer<UInt32>
  ) {
    var firstCount = 0
    var secondCount = 0
    while firstCount < 256 || secondCount < 256 {
      var laneIndex = 0
      while laneIndex < 17 && (firstCount < 256 || secondCount < 256) {
        let words = state[laneIndex]
        var byteIndex = 0
        while byteIndex < 8 && (firstCount < 256 || secondCount < 256) {
          let shift = UInt64(byteIndex * 8)
          Self.appendMLDSAShortByteEta2(
            UInt8(truncatingIfNeeded: words[0] >> shift),
            into: first,
            count: &firstCount
          )
          Self.appendMLDSAShortByteEta2(
            UInt8(truncatingIfNeeded: words[1] >> shift),
            into: second,
            count: &secondCount
          )
          byteIndex += 1
        }
        laneIndex += 1
      }
      if firstCount < 256 || secondCount < 256 {
        permute()
      }
    }
  }

  @inline(__always)
  private static func suffixLane(_ suffix: (UInt8, UInt8)) -> UInt64 {
    UInt64(suffix.0) | (UInt64(suffix.1) << 8) | (UInt64(0x1F) << 16)
  }

  @inline(__always)
  private static func nonceLane(_ nonce: UInt8) -> UInt64 {
    UInt64(nonce) | (UInt64(0x1F) << 8)
  }

  @inline(__always)
  private static func mlDSANonceLane(_ nonce: UInt16) -> UInt64 {
    UInt64(nonce) | (UInt64(0x1F) << 16)
  }

  @inline(__always)
  private static func appendMLDSAMatrixCandidate(
    _ candidate: UInt64,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    let value = candidate & 0x7F_FFFF
    if value < 8_380_417 && count < 256 {
      polynomial[count] = UInt32(truncatingIfNeeded: value)
      count += 1
    }
  }

  @inline(__always)
  private static func appendMLDSAMatrixCandidateWithCapacity(
    _ candidate: UInt64,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    // The caller reserves room for all eight candidates in the current chunk.
    // A rejected value may occupy the next uncommitted slot temporarily; the
    // next accepted value overwrites it before the polynomial is observed.
    let value = candidate & 0x7F_FFFF
    polynomial[count] = UInt32(truncatingIfNeeded: value)
    count += value < 8_380_417 ? 1 : 0
  }

  @_transparent
  private static func appendMLDSAMatrixCandidates(
    _ first: UInt64,
    _ second: UInt64,
    _ third: UInt64,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    // Three little-endian lanes contain eight consecutive 24-bit candidates.
    // The top bit is masked as required by FIPS 204 rejection sampling.
    if count <= 248 {
      appendMLDSAMatrixCandidateWithCapacity(first, into: polynomial, count: &count)
      appendMLDSAMatrixCandidateWithCapacity(
        first >> 24,
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        (first >> 48) | (second << 16),
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        second >> 8,
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        second >> 32,
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        (second >> 56) | (third << 8),
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        third >> 16,
        into: polynomial,
        count: &count
      )
      appendMLDSAMatrixCandidateWithCapacity(
        third >> 40,
        into: polynomial,
        count: &count
      )
      return
    }
    appendMLDSAMatrixCandidate(first, into: polynomial, count: &count)
    appendMLDSAMatrixCandidate(first >> 24, into: polynomial, count: &count)
    appendMLDSAMatrixCandidate(
      (first >> 48) | (second << 16),
      into: polynomial,
      count: &count
    )
    appendMLDSAMatrixCandidate(second >> 8, into: polynomial, count: &count)
    appendMLDSAMatrixCandidate(second >> 32, into: polynomial, count: &count)
    appendMLDSAMatrixCandidate(
      (second >> 56) | (third << 8),
      into: polynomial,
      count: &count
    )
    appendMLDSAMatrixCandidate(third >> 16, into: polynomial, count: &count)
    appendMLDSAMatrixCandidate(third >> 40, into: polynomial, count: &count)
  }

  @inline(__always)
  private static func appendMLDSAShortByteEta4(
    _ byte: UInt8,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    if count <= 254 {
      appendMLDSAShortCandidateEta4WithCapacity(
        UInt32(byte & 0x0F),
        into: polynomial,
        count: &count
      )
      appendMLDSAShortCandidateEta4WithCapacity(
        UInt32(byte >> 4),
        into: polynomial,
        count: &count
      )
      return
    }
    appendMLDSAShortCandidateEta4(
      UInt32(byte & 0x0F),
      into: polynomial,
      count: &count
    )
    appendMLDSAShortCandidateEta4(
      UInt32(byte >> 4),
      into: polynomial,
      count: &count
    )
  }

  @inline(__always)
  private static func appendMLDSAShortCandidateEta4WithCapacity(
    _ candidate: UInt32,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    // The caller reserves two slots for the byte. Rejected nibbles can write to
    // the next uncommitted slot because a later accepted nibble overwrites it.
    polynomial[count] = candidate <= 4 ? 4 - candidate : 8_380_421 - candidate
    count += candidate < 9 ? 1 : 0
  }

  @inline(__always)
  private static func appendMLDSAShortCandidateEta4(
    _ candidate: UInt32,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    if candidate < 9 && count < 256 {
      polynomial[count] = candidate <= 4 ? 4 - candidate : 8_380_421 - candidate
      count += 1
    }
  }

  @inline(__always)
  private static func appendMLDSAShortByteEta2(
    _ byte: UInt8,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    if count <= 254 {
      appendMLDSAShortCandidateEta2WithCapacity(
        UInt32(byte & 0x0F),
        into: polynomial,
        count: &count
      )
      appendMLDSAShortCandidateEta2WithCapacity(
        UInt32(byte >> 4),
        into: polynomial,
        count: &count
      )
      return
    }
    appendMLDSAShortCandidateEta2(
      UInt32(byte & 0x0F),
      into: polynomial,
      count: &count
    )
    appendMLDSAShortCandidateEta2(
      UInt32(byte >> 4),
      into: polynomial,
      count: &count
    )
  }

  @inline(__always)
  private static func appendMLDSAShortCandidateEta2WithCapacity(
    _ candidate: UInt32,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    let reduced: UInt32
    if candidate >= 10 {
      reduced = candidate - 10
    } else if candidate >= 5 {
      reduced = candidate - 5
    } else {
      reduced = candidate
    }
    polynomial[count] = reduced <= 2 ? 2 - reduced : 8_380_419 - reduced
    count += candidate < 15 ? 1 : 0
  }

  @inline(__always)
  private static func appendMLDSAShortCandidateEta2(
    _ candidate: UInt32,
    into polynomial: UnsafeMutablePointer<UInt32>,
    count: inout Int
  ) {
    if candidate < 15 && count < 256 {
      let reduced: UInt32
      if candidate >= 10 {
        reduced = candidate - 10
      } else if candidate >= 5 {
        reduced = candidate - 5
      } else {
        reduced = candidate
      }
      polynomial[count] = reduced <= 2 ? 2 - reduced : 8_380_419 - reduced
      count += 1
    }
  }

  @inline(__always)
  private static func storeCBDEta2(
    _ word: UInt64,
    coefficientIndex: Int,
    into polynomial: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>
  ) {
    let pairCounts =
      (word & 0x5555_5555_5555_5555)
      &+ ((word >> 1) & 0x5555_5555_5555_5555)
    #if os(macOS) && arch(arm64) && canImport(simd)
      let bytes = unsafeBitCast(pairCounts, to: SIMD8<UInt8>.self)
      let lowPositive = SIMD8<UInt16>(
        truncatingIfNeeded: bytes & SIMD8(repeating: 0x03)
      )
      let lowNegative = SIMD8<UInt16>(
        truncatingIfNeeded: (bytes &>> SIMD8(repeating: 2)) & SIMD8(repeating: 0x03)
      )
      let highPositive = SIMD8<UInt16>(
        truncatingIfNeeded: (bytes &>> SIMD8(repeating: 4)) & SIMD8(repeating: 0x03)
      )
      let highNegative = SIMD8<UInt16>(
        truncatingIfNeeded: bytes &>> SIMD8(repeating: 6)
      )
      let low = canonicalEta2Difference(lowPositive, lowNegative)
      let high = canonicalEta2Difference(highPositive, highNegative)
      var firstHalf = vzip1q_u16(low, high)
      var secondHalf = vzip2q_u16(low, high)

      // The destination has sixteen initialized coefficients beginning at the
      // validated coefficientIndex. Raw copies support its eight-byte owner
      // alignment, borrow each local SIMD value synchronously, and do not bind,
      // retain, or escape either pointer.
      withUnsafeBytes(of: &firstHalf) { source in
        UnsafeMutableRawPointer(polynomial.advanced(by: coefficientIndex))
          .copyMemory(from: source.baseAddress.unsafelyUnwrapped, byteCount: 16)
      }
      withUnsafeBytes(of: &secondHalf) { source in
        UnsafeMutableRawPointer(polynomial.advanced(by: coefficientIndex + 8))
          .copyMemory(from: source.baseAddress.unsafelyUnwrapped, byteCount: 16)
      }
    #else
      var index = 0
      while index < 16 {
        let shift = UInt64(index * 4)
        let positive = Int32((pairCounts >> shift) & 0x03)
        let negative = Int32((pairCounts >> (shift + 2)) & 0x03)
        let difference = positive - negative
        polynomial[coefficientIndex + index] = MLKEMArithmetic.Coefficient(
          truncatingIfNeeded:
            difference + ((difference >> 31) & Int32(MLKEMArithmetic.modulus))
        )
        index += 1
      }
    #endif
  }

  #if os(macOS) && arch(arm64) && canImport(simd)
    @inline(__always)
    private static func canonicalEta2Difference(
      _ positive: SIMD8<UInt16>,
      _ negative: SIMD8<UInt16>
    ) -> SIMD8<UInt16> {
      let modulus = SIMD8<UInt16>(repeating: MLKEMArithmetic.modulus)
      let value = positive &+ modulus &- negative
      let subtracted = value &- modulus
      let mask =
        SIMD8<UInt16>(repeating: 0)
        &- (subtracted &>> SIMD8(repeating: 15))
      return (mask & value) | (~mask & subtracted)
    }
  #endif

  @inline(__always)
  private static func appendCandidate(
    _ candidate: UInt64,
    into polynomial: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>,
    count: inout Int
  ) {
    if candidate < UInt64(MLKEMArithmetic.modulus) && count < 256 {
      polynomial[count] = MLKEMArithmetic.Coefficient(truncatingIfNeeded: candidate)
      count += 1
    }
  }

  @inline(__always)
  private static func appendCandidateWithCapacity(
    _ candidate: UInt64,
    into polynomial: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>,
    count: inout Int
  ) {
    // The caller reserves room for all sixteen public matrix candidates in
    // the chunk. A rejected value may transiently occupy the next uncommitted
    // slot, which the next accepted value overwrites before the span is read.
    polynomial[count] = MLKEMArithmetic.Coefficient(truncatingIfNeeded: candidate)
    count += candidate < UInt64(MLKEMArithmetic.modulus) ? 1 : 0
  }

  @inline(__always)
  private static func append24ByteCandidates(
    _ first: UInt64,
    _ second: UInt64,
    _ third: UInt64,
    into polynomial: UnsafeMutablePointer<MLKEMArithmetic.Coefficient>,
    count: inout Int
  ) {
    // Three little-endian lanes contain exactly sixteen consecutive 12-bit
    // candidates. Fixed shifts avoid per-candidate lane division and the two
    // boundary branches at bit offsets 60 and 120.
    if count <= 240 {
      appendCandidateWithCapacity(first & 0x0FFF, into: polynomial, count: &count)
      appendCandidateWithCapacity(
        (first >> 12) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (first >> 24) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (first >> 36) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (first >> 48) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        ((first >> 60) | (second << 4)) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (second >> 8) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (second >> 20) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (second >> 32) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (second >> 44) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        ((second >> 56) | (third << 8)) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (third >> 4) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (third >> 16) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (third >> 28) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (third >> 40) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      appendCandidateWithCapacity(
        (third >> 52) & 0x0FFF,
        into: polynomial,
        count: &count
      )
      return
    }

    appendCandidate(first & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((first >> 12) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((first >> 24) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((first >> 36) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((first >> 48) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate(
      ((first >> 60) | (second << 4)) & 0x0FFF,
      into: polynomial,
      count: &count
    )
    appendCandidate((second >> 8) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((second >> 20) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((second >> 32) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((second >> 44) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate(
      ((second >> 56) | (third << 8)) & 0x0FFF,
      into: polynomial,
      count: &count
    )
    appendCandidate((third >> 4) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((third >> 16) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((third >> 28) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((third >> 40) & 0x0FFF, into: polynomial, count: &count)
    appendCandidate((third >> 52) & 0x0FFF, into: polynomial, count: &count)
  }

  @inline(__always)
  private mutating func permute() {
    // Unsafe boundary invariants:
    // - This noncopyable value uniquely owns exactly 25 initialized SIMD2<UInt64> lanes.
    // - Every accessed index is in 0..<25 and mutation remains exclusive.
    var round = 0
    while round < 24 {
      let c0 = Self.xor5(state[0], state[5], state[10], state[15], state[20])
      let c1 = Self.xor5(state[1], state[6], state[11], state[16], state[21])
      let c2 = Self.xor5(state[2], state[7], state[12], state[17], state[22])
      let c3 = Self.xor5(state[3], state[8], state[13], state[18], state[23])
      let c4 = Self.xor5(state[4], state[9], state[14], state[19], state[24])
      let d0 = Self.xorRotatedLeft1(c4, c1)
      let d1 = Self.xorRotatedLeft1(c0, c2)
      let d2 = Self.xorRotatedLeft1(c1, c3)
      let d3 = Self.xorRotatedLeft1(c2, c4)
      let d4 = Self.xorRotatedLeft1(c3, c0)

      state[0] ^= d0
      state[5] ^= d0
      state[10] ^= d0
      state[15] ^= d0
      state[20] ^= d0
      state[1] ^= d1
      state[6] ^= d1
      state[11] ^= d1
      state[16] ^= d1
      state[21] ^= d1
      state[2] ^= d2
      state[7] ^= d2
      state[12] ^= d2
      state[17] ^= d2
      state[22] ^= d2
      state[3] ^= d3
      state[8] ^= d3
      state[13] ^= d3
      state[18] ^= d3
      state[23] ^= d3
      state[4] ^= d4
      state[9] ^= d4
      state[14] ^= d4
      state[19] ^= d4
      state[24] ^= d4

      var previous = state[1]
      Self.move(&previous, into: &state[10], rotation: 1)
      Self.move(&previous, into: &state[7], rotation: 3)
      Self.move(&previous, into: &state[11], rotation: 6)
      Self.move(&previous, into: &state[17], rotation: 10)
      Self.move(&previous, into: &state[18], rotation: 15)
      Self.move(&previous, into: &state[3], rotation: 21)
      Self.move(&previous, into: &state[5], rotation: 28)
      Self.move(&previous, into: &state[16], rotation: 36)
      Self.move(&previous, into: &state[8], rotation: 45)
      Self.move(&previous, into: &state[21], rotation: 55)
      Self.move(&previous, into: &state[24], rotation: 2)
      Self.move(&previous, into: &state[4], rotation: 14)
      Self.move(&previous, into: &state[15], rotation: 27)
      Self.move(&previous, into: &state[23], rotation: 41)
      Self.move(&previous, into: &state[19], rotation: 56)
      Self.move(&previous, into: &state[13], rotation: 8)
      Self.move(&previous, into: &state[12], rotation: 25)
      Self.move(&previous, into: &state[2], rotation: 43)
      Self.move(&previous, into: &state[20], rotation: 62)
      Self.move(&previous, into: &state[14], rotation: 18)
      Self.move(&previous, into: &state[22], rotation: 39)
      Self.move(&previous, into: &state[9], rotation: 61)
      Self.move(&previous, into: &state[6], rotation: 20)
      Self.move(&previous, into: &state[1], rotation: 44)

      var row = 0
      while row < 25 {
        // Load the complete row before the Chi step so each lane is read once.
        // This keeps the unsafe state access bounded while allowing the ARM64
        // backend to retain the five SIMD lanes in registers across all stores.
        let original0 = state[row]
        let original1 = state[row + 1]
        let original2 = state[row + 2]
        let original3 = state[row + 3]
        let original4 = state[row + 4]
        state[row] = Self.bitClearAndXor(original0, original2, original1)
        state[row + 1] = Self.bitClearAndXor(
          original1, original3, original2
        )
        state[row + 2] = Self.bitClearAndXor(
          original2, original4, original3
        )
        state[row + 3] = Self.bitClearAndXor(original3, original0, original4)
        state[row + 4] = Self.bitClearAndXor(original4, original1, original0)
        row += 5
      }

      state[0] ^= SIMD2(repeating: Self.roundConstants[round])
      round += 1
    }
  }

  @inline(__always)
  private static func xor5(
    _ first: SIMD2<UInt64>,
    _ second: SIMD2<UInt64>,
    _ third: SIMD2<UInt64>,
    _ fourth: SIMD2<UInt64>,
    _ fifth: SIMD2<UInt64>
  ) -> SIMD2<UInt64> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return veor3q_u64(veor3q_u64(first, second, third), fourth, fifth)
    #else
      return first ^ second ^ third ^ fourth ^ fifth
    #endif
  }

  @inline(__always)
  private static func xorRotatedLeft1(
    _ first: SIMD2<UInt64>,
    _ second: SIMD2<UInt64>
  ) -> SIMD2<UInt64> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vrax1q_u64(first, second)
    #else
      return first ^ second.rotatingLeft(by: 1)
    #endif
  }

  @inline(__always)
  private static func bitClearAndXor(
    _ first: SIMD2<UInt64>,
    _ second: SIMD2<UInt64>,
    _ complement: SIMD2<UInt64>
  ) -> SIMD2<UInt64> {
    #if os(macOS) && arch(arm64) && canImport(simd)
      return vbcaxq_u64(first, second, complement)
    #else
      return first ^ (second & ~complement)
    #endif
  }

  @inline(__always)
  private static func move(
    _ previous: inout SIMD2<UInt64>,
    into destination: inout SIMD2<UInt64>,
    rotation: UInt64
  ) {
    let displaced = destination
    destination = previous.rotatingLeft(by: rotation)
    previous = displaced
  }

  deinit {
    // Unsafe boundary invariants:
    // - No pointer derived from state escapes this noncopyable owner.
    // - Secret state is wiped before exactly-once deallocation; public matrix
    //   expansion state contains no secret and needs no redundant volatile wipe.
    switch sensitivity {
    case .secret:
      SecureWipe.eraseUInt64Words(
        UnsafeMutableRawPointer(state),
        wordCount: 25 * 2
      )
    case .publicData:
      break
    }
    state.deinitialize(count: 25)
    state.deallocate()
  }
}

extension SIMD2 where Scalar == UInt64 {
  @inline(__always)
  fileprivate func rotatingLeft(by amount: UInt64) -> SIMD2<UInt64> {
    let left = SIMD2<UInt64>(repeating: amount)
    let right = SIMD2<UInt64>(repeating: 64 - amount)
    return (self &<< left) | (self &>> right)
  }
}
