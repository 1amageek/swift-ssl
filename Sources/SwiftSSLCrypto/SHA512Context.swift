import SwiftSSLCore

/// Incremental SHA-512 context. The scalar compressor is shared by SHA-512
/// and the SHA-384 truncated variant; target-specific acceleration is a later
/// backend decision and does not change this state contract.
public struct SHA512Context: ~Copyable, HashContext, HMACSHA2Context {
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
              inputCount <= Self.maximumInputByteCount - totalByteCount else {
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

    package mutating func finalizeInPlace(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
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
            pendingBytes[120 + index - 1] = UInt8(truncatingIfNeeded: (totalByteCount << 3) >> UInt64((7 - index + 1) * 8))
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

    private mutating func copy(_ input: Span<UInt8>, from sourceOffset: Int, count: Int, into destinationOffset: Int) {
        guard count > 0 else { return }
        input.withUnsafeBytes { source in
            pendingBytes.withUnsafeMutableBufferPointer { destination in
                destination.baseAddress!.advanced(by: destinationOffset)
                    .update(
                        from: source.baseAddress!.assumingMemoryBound(to: UInt8.self).advanced(by: sourceOffset),
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
            pendingBytes.replaceSubrange((start + 1)..<end, with: repeatElement(UInt8(0), count: end - start - 1))
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
        var a = state[0], b = state[1], c = state[2], d = state[3]
        var e = state[4], f = state[5], g = state[6], h = state[7]
        index = 0
        while index < 80 {
            let s1 = e.rotatedRight(by: 14) ^ e.rotatedRight(by: 18) ^ e.rotatedRight(by: 41)
            let ch = (e & f) ^ (~e & g)
            let temp1 = h &+ s1 &+ ch &+ Self.roundConstants[index] &+ schedule[index]
            let s0 = a.rotatedRight(by: 28) ^ a.rotatedRight(by: 34) ^ a.rotatedRight(by: 39)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj
            h = g; g = f; f = e; e = d &+ temp1
            d = c; c = b; b = a; a = temp1 &+ temp2
            index += 1
        }
        state[0] &+= a; state[1] &+= b; state[2] &+= c; state[3] &+= d
        state[4] &+= e; state[5] &+= f; state[6] &+= g; state[7] &+= h
        SecureWipe.erase(schedule.withUnsafeMutableBytes { $0.baseAddress! }, byteCount: schedule.count * 8)
    }

    private static func writeBigEndian(_ value: UInt64, into output: inout MutableSpan<UInt8>, offset: Int) {
        var index = 0
        while index < 8 {
            output[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64((7 - index) * 8))
            index += 1
        }
    }

    private static let sha512InitialState: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    fileprivate static let sha384InitialState: [UInt64] = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    ]
    private static let roundConstants: [UInt64] = [
        0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
        0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
        0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
        0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
        0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
        0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
        0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
        0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
        0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
        0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
        0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
        0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
        0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
    ]
}

private extension UInt64 {
    @inline(__always) func rotatedRight(by amount: UInt64) -> UInt64 {
        (self >> amount) | (self << (64 - amount))
    }
}

public struct SHA384Context: ~Copyable, HashContext, HMACSHA2Context {
    public static let digestByteCount = 48
    private var inner: SHA512Context

    public init() { inner = SHA512Context(initialState: SHA512Context.sha384InitialState) }
    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) { try inner.update(input) }
    public borrowing func clone() -> SHA384Context {
        var result = SHA384Context()
        result.inner = inner.clone()
        return result
    }
    public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        try finalizeInPlace(into: &output)
    }
    package mutating func finalizeInPlace(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
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
        while index < Self.digestByteCount { output[index] = temporary[index]; index += 1 }
    }
    package mutating func eraseSensitiveState() { inner.eraseSensitiveState() }
}
