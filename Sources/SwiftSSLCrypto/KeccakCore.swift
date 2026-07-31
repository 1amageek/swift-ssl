import SwiftSSLCore

/// Internal Keccak-f[1600] sponge storage shared by SHA-3 and SHAKE.
///
/// The state is ordinary public-data storage, not secret material. Absorption
/// and squeezing operate on scoped spans; no pointer derived from a span is
/// retained after the operation. The rate is always a whole number of lanes,
/// and every lane load/store uses little-endian byte order from FIPS 202.
struct KeccakCore {
    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008,
    ]

    private static let rotationOffsets: [Int] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]

    private var state: ContiguousArray<UInt64>
    private var pending: ContiguousArray<UInt8>
    private let rateByteCount: Int
    private let domainSeparator: UInt8
    private var totalByteCount: UInt64

    init(rateByteCount: Int, domainSeparator: UInt8) {
        precondition(rateByteCount > 0 && rateByteCount <= 200 && rateByteCount % 8 == 0)
        state = ContiguousArray(repeating: 0, count: 25)
        pending = ContiguousArray()
        pending.reserveCapacity(rateByteCount)
        self.rateByteCount = rateByteCount
        self.domainSeparator = domainSeparator
        totalByteCount = 0
    }

    mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        let byteCount = UInt64(input.count)
        guard totalByteCount <= UInt64.max - byteCount else {
            throw .inputTooLong(limit: UInt64.max)
        }
        totalByteCount += byteCount

        var offset = 0
        if !pending.isEmpty {
            let required = rateByteCount - pending.count
            let copied = Swift.min(required, input.count)
            var index = 0
            while index < copied {
                pending.append(input[offset + index])
                index += 1
            }
            offset += copied
            if pending.count == rateByteCount {
                let block = pending
                pending.removeAll(keepingCapacity: true)
                absorb(block.span)
            }
        }

        while input.count - offset >= rateByteCount {
            absorb(input.extracting(offset..<(offset + rateByteCount)))
            offset += rateByteCount
        }

        while offset < input.count {
            pending.append(input[offset])
            offset += 1
        }
    }

    mutating func finalize(into output: inout MutableSpan<UInt8>) {
        pending.append(domainSeparator)
        while pending.count < rateByteCount {
            pending.append(0)
        }
        pending[rateByteCount - 1] |= 0x80
        let block = pending
        pending.removeAll(keepingCapacity: true)
        absorb(block.span)

        var written = 0
        while written < output.count {
            let available = Swift.min(rateByteCount, output.count - written)
            var index = 0
            while index < available {
                let laneIndex = index / 8
                let shift = UInt64((index % 8) * 8)
                output[written + index] = UInt8(truncatingIfNeeded: state[laneIndex] >> shift)
                index += 1
            }
            written += available
            if written < output.count {
                permute()
            }
        }
    }

    private mutating func absorb(_ block: Span<UInt8>) {
        var byteIndex = 0
        while byteIndex < rateByteCount {
            let laneIndex = byteIndex / 8
            let shift = UInt64((byteIndex % 8) * 8)
            state[laneIndex] ^= UInt64(block[byteIndex]) << shift
            byteIndex += 1
        }
        permute()
    }

    @inline(__always)
    private mutating func permute() {
        var round = 0
        while round < 24 {
            var c = ContiguousArray<UInt64>(repeating: 0, count: 5)
            var x = 0
            while x < 5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                x += 1
            }

            var d = ContiguousArray<UInt64>(repeating: 0, count: 5)
            x = 0
            while x < 5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotatingLeft(by: 1)
                x += 1
            }
            var lane = 0
            while lane < 25 {
                state[lane] ^= d[lane % 5]
                lane += 1
            }

            var b = ContiguousArray<UInt64>(repeating: 0, count: 25)
            x = 0
            while x < 5 {
                var y = 0
                while y < 5 {
                    let source = x + 5 * y
                    let destinationX = y
                    let destinationY = (2 * x + 3 * y) % 5
                    b[destinationX + 5 * destinationY] = state[source].rotatingLeft(
                        by: Self.rotationOffsets[source]
                    )
                    y += 1
                }
                x += 1
            }

            x = 0
            while x < 5 {
                var y = 0
                while y < 5 {
                    let index = x + 5 * y
                    state[index] = b[index] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                    y += 1
                }
                x += 1
            }
            state[0] ^= Self.roundConstants[round]
            round += 1
        }
    }
}

private extension UInt64 {
    @inline(__always)
    func rotatingLeft(by amount: Int) -> UInt64 {
        let shift = UInt64(amount)
        return (self << shift) | (self >> (64 - shift))
    }
}
