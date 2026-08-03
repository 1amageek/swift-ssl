import SSLCore

/// Bounded, offset-aware reassembly for one QUIC CRYPTO stream.
///
/// RFC 9000 defines a separate ordered CRYPTO byte stream for every
/// encryption level. One reassembler therefore owns exactly one level. Input
/// is copied once because the caller's frame storage is borrowed and may not
/// outlive `receive`; contiguous delivery borrows the stable owner without an
/// additional materialization.
public struct QUICCryptoStreamReassembler: QUICCryptoStreamReassembling, ~Copyable, Sendable {
    public static let defaultMaximumBufferedByteCount = 1 * 1024 * 1024
    public static let maximumPermittedBufferByteCount = 16 * 1024 * 1024
    public static let maximumQUICOffset: UInt64 = (UInt64(1) << 62) - 1

    public let encryptionLevel: QUICHandshakeEncryptionLevel
    public let maximumBufferedByteCount: Int

    private var mirroredStorage: ContiguousArray<UInt8>
    private var receivedWords: ContiguousArray<UInt64>
    private var readOffset: UInt64
    private var contiguousEndOffset: UInt64
    private var uniqueUnconsumedByteCount: Int

    public init(
        encryptionLevel: QUICHandshakeEncryptionLevel,
        maximumBufferedByteCount: Int = Self.defaultMaximumBufferedByteCount
    ) throws(QUICCryptoStreamError) {
        guard maximumBufferedByteCount > 0,
              maximumBufferedByteCount <= Self.maximumPermittedBufferByteCount else {
            throw .invalidBufferLimit(maximumBufferedByteCount)
        }
        self.encryptionLevel = encryptionLevel
        self.maximumBufferedByteCount = maximumBufferedByteCount
        mirroredStorage = ContiguousArray(
            repeating: 0,
            count: maximumBufferedByteCount * 2
        )
        receivedWords = ContiguousArray(
            repeating: 0,
            count: (maximumBufferedByteCount + 63) / 64
        )
        readOffset = 0
        contiguousEndOffset = 0
        uniqueUnconsumedByteCount = 0
    }

    /// Absolute stream offset of the first byte not yet discarded by TLS.
    public var nextReadOffset: UInt64 { readOffset }

    /// Bytes currently available as one zero-copy contiguous borrow.
    public var contiguousByteCount: Int {
        Int(contiguousEndOffset - readOffset)
    }

    /// Unique received bytes not yet discarded, including out-of-order data.
    public var bufferedByteCount: Int { uniqueUnconsumedByteCount }

    /// Inserts one CRYPTO frame payload transactionally.
    ///
    /// Exact retransmissions and equal overlaps are accepted. If any already
    /// received byte differs, no byte from this call is committed.
    public mutating func receive(
        offset: UInt64,
        bytes: Span<UInt8>
    ) throws(QUICCryptoStreamError) {
        guard offset <= Self.maximumQUICOffset else {
            throw .offsetOutOfRange(offset)
        }
        let byteCount = UInt64(bytes.count)
        let (endOffset, overflow) = offset.addingReportingOverflow(byteCount)
        guard !overflow, endOffset <= Self.maximumQUICOffset else {
            throw .offsetOutOfRange(offset)
        }
        guard !bytes.isEmpty else { return }
        guard endOffset > readOffset else { return }

        let effectiveOffset = Swift.max(offset, readOffset)
        let inputStart = Int(effectiveOffset - offset)
        let windowEnd = readOffset + UInt64(maximumBufferedByteCount)
        guard endOffset <= windowEnd else {
            throw .bufferExceeded(
                limit: maximumBufferedByteCount,
                endOffset: endOffset
            )
        }

        var inputIndex = inputStart
        var absoluteOffset = effectiveOffset
        while inputIndex < bytes.count {
            let storageIndex = storageIndex(for: absoluteOffset)
            if isReceived(storageIndex), mirroredStorage[storageIndex] != bytes[inputIndex] {
                throw .conflictingOverlap(offset: absoluteOffset)
            }
            inputIndex += 1
            absoluteOffset += 1
        }

        inputIndex = inputStart
        absoluteOffset = effectiveOffset
        while inputIndex < bytes.count {
            let storageIndex = storageIndex(for: absoluteOffset)
            if !isReceived(storageIndex) {
                let byte = bytes[inputIndex]
                mirroredStorage[storageIndex] = byte
                mirroredStorage[storageIndex + maximumBufferedByteCount] = byte
                markReceived(storageIndex)
                uniqueUnconsumedByteCount += 1
            }
            inputIndex += 1
            absoluteOffset += 1
        }

        while contiguousEndOffset < windowEnd,
              isReceived(storageIndex(for: contiguousEndOffset)) {
            contiguousEndOffset += 1
        }
    }

    /// Borrows every currently contiguous byte without advancing the stream.
    public borrowing func withContiguousBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        let start = storageIndex(for: readOffset)
        return try body(
            mirroredStorage.span.extracting(start..<(start + contiguousByteCount))
        )
    }

    /// Advances the TLS consumer after it has processed a borrowed prefix.
    public mutating func discardContiguousBytes(
        count: Int
    ) throws(QUICCryptoStreamError) {
        let available = contiguousByteCount
        guard count >= 0, count <= available else {
            throw .discardOutOfRange(available: available, requested: count)
        }
        var discarded = 0
        while discarded < count {
            clearReceived(storageIndex(for: readOffset + UInt64(discarded)))
            discarded += 1
        }
        readOffset += UInt64(count)
        uniqueUnconsumedByteCount -= count
    }

    @inline(__always)
    private borrowing func storageIndex(for offset: UInt64) -> Int {
        Int(offset % UInt64(maximumBufferedByteCount))
    }

    @inline(__always)
    private borrowing func isReceived(_ index: Int) -> Bool {
        let wordIndex = index >> 6
        let bitIndex = UInt64(index & 63)
        return (receivedWords[wordIndex] & (UInt64(1) << bitIndex)) != 0
    }

    @inline(__always)
    private mutating func markReceived(_ index: Int) {
        let wordIndex = index >> 6
        let bitIndex = UInt64(index & 63)
        receivedWords[wordIndex] |= UInt64(1) << bitIndex
    }

    @inline(__always)
    private mutating func clearReceived(_ index: Int) {
        let wordIndex = index >> 6
        let bitIndex = UInt64(index & 63)
        receivedWords[wordIndex] &= ~(UInt64(1) << bitIndex)
    }
}
