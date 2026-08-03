import SSLCore
import SSLQUIC
import SSLTLS
import XCTest

final class QUICTLSHandshakeStreamTests: XCTestCase {
    func testFramesOutOfOrderCryptoDataWithoutOutputCopy() throws {
        var stream = try QUICTLSHandshakeStream.make(
            encryptionLevel: .handshake,
            maximumBufferedByteCount: 32,
            maximumMessageByteCount: 16
        )
        let tail: ContiguousArray<UInt8> = [0xAA, 0xBB, 0xCC]
        let header: ContiguousArray<UInt8> = [1, 0, 0, 3]
        try stream.receive(offset: 4, bytes: tail.span)
        XCTAssertNil(try stream.withNextMessage { copy($0) })
        try stream.receive(offset: 0, bytes: header.span)

        XCTAssertEqual(
            try stream.withNextMessage { copy($0) },
            [1, 0, 0, 3, 0xAA, 0xBB, 0xCC]
        )
        XCTAssertEqual(stream.nextReadOffset, 0)
        try stream.discardNextMessage()
        XCTAssertEqual(stream.nextReadOffset, 7)
        XCTAssertEqual(stream.bufferedByteCount, 0)
    }

    func testSeparatesConsecutiveMessages() throws {
        var stream = try QUICTLSHandshakeStream.make(
            encryptionLevel: .initial,
            maximumBufferedByteCount: 32,
            maximumMessageByteCount: 16
        )
        let messages: ContiguousArray<UInt8> = [
            1, 0, 0, 1, 0xAA,
            2, 0, 0, 2, 0xBB, 0xCC,
        ]
        try stream.receive(offset: 0, bytes: messages.span)

        XCTAssertEqual(
            try stream.withNextMessage { copy($0) },
            [1, 0, 0, 1, 0xAA]
        )
        try stream.discardNextMessage()
        XCTAssertEqual(
            try stream.withNextMessage { copy($0) },
            [2, 0, 0, 2, 0xBB, 0xCC]
        )
    }

    func testRejectsDiscardOfIncompleteMessage() throws {
        var stream = try QUICTLSHandshakeStream.make(
            encryptionLevel: .handshake,
            maximumBufferedByteCount: 16,
            maximumMessageByteCount: 16
        )
        let header: ContiguousArray<UInt8> = [1, 0, 0, 2]
        try stream.receive(offset: 0, bytes: header.span)

        do {
            try stream.discardNextMessage()
            XCTFail("incomplete TLS handshake message was discarded")
        } catch {
            XCTAssertEqual(
                error,
                .incompleteMessage(minimumAdditionalByteCount: 2)
            )
        }
        XCTAssertEqual(stream.nextReadOffset, 0)
    }

    func testMapsOversizedMessageAndOverlapFailures() throws {
        var stream = try QUICTLSHandshakeStream.make(
            encryptionLevel: .oneRTT,
            maximumBufferedByteCount: 16,
            maximumMessageByteCount: 8
        )
        let oversizedHeader: ContiguousArray<UInt8> = [1, 0, 0, 5]
        try stream.receive(offset: 0, bytes: oversizedHeader.span)
        do {
            _ = try stream.nextMessageStatus()
            XCTFail("oversized TLS handshake message was framed")
        } catch {
            XCTAssertEqual(
                error,
                .framing(.messageTooLarge(maximum: 8, actual: 9))
            )
        }

        let conflict: ContiguousArray<UInt8> = [2]
        do {
            try stream.receive(offset: 0, bytes: conflict.span)
            XCTFail("conflicting QUIC CRYPTO byte was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .reassembly(.conflictingOverlap(offset: 0))
            )
        }
    }

    func testRejectsIncompatibleLimits() throws {
        do {
            _ = try QUICTLSHandshakeStream.make(
                encryptionLevel: .initial,
                maximumBufferedByteCount: 8,
                maximumMessageByteCount: 9
            )
            XCTFail("message limit larger than the reassembly window was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .incompatibleLimits(
                    maximumBufferedByteCount: 8,
                    maximumMessageByteCount: 9
                )
            )
        }
    }

    func testPreservesConfigurationFailureTypes() throws {
        do {
            _ = try QUICTLSHandshakeStream.make(
                encryptionLevel: .initial,
                maximumBufferedByteCount: 0,
                maximumMessageByteCount: 4
            )
            XCTFail("zero-sized reassembly window was accepted")
        } catch {
            XCTAssertEqual(error, .reassembly(.invalidBufferLimit(0)))
        }

        do {
            _ = try QUICTLSHandshakeStream.make(
                encryptionLevel: .initial,
                maximumBufferedByteCount: 8,
                maximumMessageByteCount: 3
            )
            XCTFail("TLS message limit smaller than its header was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .framing(.invalidMaximumMessageByteCount(3))
            )
        }
    }

    private static func copy(_ bytes: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }

    private func copy(_ bytes: Span<UInt8>) -> [UInt8] {
        Self.copy(bytes)
    }
}
