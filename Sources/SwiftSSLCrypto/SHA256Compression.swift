enum SHA256Compression {
    @inline(__always)
    static func compressInputBlocks(
        state: inout SIMD8<UInt32>,
        input: Span<UInt8>,
        at offset: Int,
        blockCount: Int
    ) {
        #if os(macOS) && arch(arm64) && canImport(simd)
        // Unsafe invariants: the caller has established `offset >= 0`,
        // `blockCount > 0`, and `blockCount * 64` bytes in `input`; therefore
        // every block offset is representable and in range. The span's owner
        // remains alive for this synchronous closure. The kernel performs
        // unaligned read-only byte loads, does not bind or mutate input memory,
        // and the derived address does not escape or cross a Sendable boundary.
        input.bytes.withUnsafeBytes { bytes in
            SHA256ARM64Kernel.compressBlocks(
                state: &state,
                blocks: bytes.baseAddress.unsafelyUnwrapped.advanced(by: offset),
                blockCount: blockCount
            )
        }
        #else
        var blockIndex = 0
        while blockIndex < blockCount {
            let blockOffset = offset + blockIndex * 64
            var initialSchedule = SIMD16<UInt32>(repeating: 0)
            var wordIndex = 0
            while wordIndex < 16 {
                let byteOffset = blockOffset + wordIndex * 4
                initialSchedule[wordIndex] =
                    (UInt32(input[unchecked: byteOffset]) << 24)
                    | (UInt32(input[unchecked: byteOffset + 1]) << 16)
                    | (UInt32(input[unchecked: byteOffset + 2]) << 8)
                    | UInt32(input[unchecked: byteOffset + 3])
                wordIndex += 1
            }
            SHA256ScalarKernel.compress(
                state: &state,
                initialSchedule: initialSchedule
            )
            blockIndex += 1
        }
        #endif
    }

    @inline(__always)
    static func compressPendingBlock(
        state: inout SIMD8<UInt32>,
        pendingBytes: borrowing SIMD64<UInt8>
    ) {
        #if os(macOS) && arch(arm64) && canImport(simd)
        withUnsafeBytes(of: pendingBytes) { bytes in
            SHA256ARM64Kernel.compressBlocks(
                state: &state,
                blocks: bytes.baseAddress.unsafelyUnwrapped,
                blockCount: 1
            )
        }
        #else
        var initialSchedule = SIMD16<UInt32>(repeating: 0)
        var index = 0
        while index < 16 {
            let byteOffset = index * 4
            initialSchedule[index] =
                (UInt32(pendingBytes[byteOffset]) << 24)
                | (UInt32(pendingBytes[byteOffset + 1]) << 16)
                | (UInt32(pendingBytes[byteOffset + 2]) << 8)
                | UInt32(pendingBytes[byteOffset + 3])
            index += 1
        }
        SHA256ScalarKernel.compress(
            state: &state,
            initialSchedule: initialSchedule
        )
        #endif
    }

    @inline(__always)
    static func compressUsingScalar(
        state: inout SIMD8<UInt32>,
        initialSchedule: SIMD16<UInt32>
    ) {
        SHA256ScalarKernel.compress(
            state: &state,
            initialSchedule: initialSchedule
        )
    }

    #if os(macOS) && arch(arm64) && canImport(simd)
    @inline(__always)
    static func compressUsingARM64SHA2(
        state: inout SIMD8<UInt32>,
        initialSchedule: SIMD16<UInt32>
    ) {
        SHA256ARM64Kernel.compress(
            state: &state,
            initialSchedule: initialSchedule
        )
    }
    #endif
}
