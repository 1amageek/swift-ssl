import SwiftSSLCore
import SwiftSSLQUIC
import XCTest

final class QUICCryptoStreamReassemblerTests: XCTestCase {
    func testReassemblesOutOfOrderDataAndBorrowsContiguousPrefix() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .handshake,
            maximumBufferedByteCount: 32
        )
        let tail: ContiguousArray<UInt8> = [4, 5]
        try stream.receive(offset: 3, bytes: tail.span)
        XCTAssertEqual(stream.contiguousByteCount, 0)
        XCTAssertEqual(stream.bufferedByteCount, 2)

        let head: ContiguousArray<UInt8> = [1, 2, 3]
        try stream.receive(offset: 0, bytes: head.span)
        XCTAssertEqual(stream.contiguousByteCount, 5)
        XCTAssertEqual(stream.bufferedByteCount, 5)
        stream.withContiguousBytes { bytes in
            XCTAssertEqual(copy(bytes), [1, 2, 3, 4, 5])
        }

        try stream.discardContiguousBytes(count: 2)
        XCTAssertEqual(stream.nextReadOffset, 2)
        XCTAssertEqual(stream.bufferedByteCount, 3)
        stream.withContiguousBytes { bytes in
            XCTAssertEqual(copy(bytes), [3, 4, 5])
        }
    }

    func testAcceptsExactRetransmissionWithoutDoubleCounting() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .initial,
            maximumBufferedByteCount: 16
        )
        let payload: ContiguousArray<UInt8> = [10, 20, 30, 40]
        try stream.receive(offset: 0, bytes: payload.span)
        try stream.receive(offset: 0, bytes: payload.span)
        let overlap: ContiguousArray<UInt8> = [20, 30]
        try stream.receive(offset: 1, bytes: overlap.span)

        XCTAssertEqual(stream.bufferedByteCount, 4)
        XCTAssertEqual(stream.contiguousByteCount, 4)
    }

    func testReusesDiscardedRingSlotsAndBorrowsAcrossWrap() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .handshake,
            maximumBufferedByteCount: 4
        )
        let first: ContiguousArray<UInt8> = [1, 2, 3, 4]
        try stream.receive(offset: 0, bytes: first.span)
        try stream.discardContiguousBytes(count: 3)

        let second: ContiguousArray<UInt8> = [5, 6, 7]
        try stream.receive(offset: 4, bytes: second.span)
        XCTAssertEqual(stream.nextReadOffset, 3)
        XCTAssertEqual(stream.contiguousByteCount, 4)
        XCTAssertEqual(stream.bufferedByteCount, 4)
        stream.withContiguousBytes { bytes in
            XCTAssertEqual(copy(bytes), [4, 5, 6, 7])
        }
    }

    func testRejectsConflictingOverlapWithoutPartialMutation() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .oneRTT,
            maximumBufferedByteCount: 16
        )
        let initial: ContiguousArray<UInt8> = [1, 2, 3]
        try stream.receive(offset: 0, bytes: initial.span)
        let conflict: ContiguousArray<UInt8> = [9, 4, 5]

        do {
            try stream.receive(offset: 2, bytes: conflict.span)
            XCTFail("conflicting CRYPTO overlap was accepted")
        } catch {
            XCTAssertEqual(error, .conflictingOverlap(offset: 2))
        }

        XCTAssertEqual(stream.bufferedByteCount, 3)
        XCTAssertEqual(stream.contiguousByteCount, 3)
        stream.withContiguousBytes { bytes in
            XCTAssertEqual(copy(bytes), [1, 2, 3])
        }
    }

    func testRejectsProtocolAndLocalBufferLimits() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .initial,
            maximumBufferedByteCount: 4
        )
        let payload: ContiguousArray<UInt8> = [1, 2]

        do {
            try stream.receive(offset: 3, bytes: payload.span)
            XCTFail("CRYPTO data beyond the local buffer was accepted")
        } catch {
            XCTAssertEqual(error, .bufferExceeded(limit: 4, endOffset: 5))
        }

        do {
            try stream.receive(
                offset: QUICCryptoStreamReassembler.maximumQUICOffset,
                bytes: payload.span
            )
            XCTFail("CRYPTO data beyond the QUIC offset limit was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .offsetOutOfRange(QUICCryptoStreamReassembler.maximumQUICOffset)
            )
        }
    }

    func testRejectsDiscardBeyondContiguousData() throws {
        var stream = try QUICCryptoStreamReassembler(
            encryptionLevel: .handshake,
            maximumBufferedByteCount: 8
        )
        let payload: ContiguousArray<UInt8> = [7, 8]
        try stream.receive(offset: 0, bytes: payload.span)

        do {
            try stream.discardContiguousBytes(count: 3)
            XCTFail("discard beyond the contiguous prefix was accepted")
        } catch {
            XCTAssertEqual(error, .discardOutOfRange(available: 2, requested: 3))
        }
        XCTAssertEqual(stream.nextReadOffset, 0)
        XCTAssertEqual(stream.contiguousByteCount, 2)
    }

    private func copy(_ bytes: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }
}
