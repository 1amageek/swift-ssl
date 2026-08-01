import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class TLS13HandshakeMessageFramerTests: XCTestCase {
    func testReportsExactHeaderBytesNeeded() throws {
        let framer = try TLS13HandshakeMessageFramer()
        let empty = ContiguousArray<UInt8>()
        let partial: ContiguousArray<UInt8> = [1, 0]

        XCTAssertEqual(
            try framer.status(for: empty.span),
            .needsMoreData(minimumAdditionalByteCount: 4)
        )
        XCTAssertEqual(
            try framer.status(for: partial.span),
            .needsMoreData(minimumAdditionalByteCount: 2)
        )
    }

    func testReportsExactBodyBytesNeeded() throws {
        let framer = try TLS13HandshakeMessageFramer()
        let bytes: ContiguousArray<UInt8> = [1, 0, 0, 3, 0xAA]

        XCTAssertEqual(
            try framer.status(for: bytes.span),
            .needsMoreData(minimumAdditionalByteCount: 2)
        )
    }

    func testReturnsOnlyFirstCompleteMessageBoundary() throws {
        let framer = try TLS13HandshakeMessageFramer()
        let bytes: ContiguousArray<UInt8> = [
            1, 0, 0, 2, 0xAA, 0xBB,
            2, 0, 0, 1, 0xCC,
        ]

        XCTAssertEqual(
            try framer.status(for: bytes.span),
            .complete(messageByteCount: 6)
        )
    }

    func testAcceptsConfiguredBoundary() throws {
        let framer = try TLS13HandshakeMessageFramer(maximumMessageByteCount: 8)
        let bytes: ContiguousArray<UInt8> = [1, 0, 0, 4, 1, 2, 3, 4]

        XCTAssertEqual(
            try framer.status(for: bytes.span),
            .complete(messageByteCount: 8)
        )
    }

    func testRejectsMessageBeyondConfiguredBoundary() throws {
        let framer = try TLS13HandshakeMessageFramer(maximumMessageByteCount: 8)
        let header: ContiguousArray<UInt8> = [1, 0, 0, 5]

        do {
            _ = try framer.status(for: header.span)
            XCTFail("oversized handshake message was accepted")
        } catch {
            XCTAssertEqual(error, .messageTooLarge(maximum: 8, actual: 9))
        }
    }

    func testRejectsInvalidConfiguredBoundaries() {
        XCTAssertThrowsError(
            try TLS13HandshakeMessageFramer(maximumMessageByteCount: 3)
        ) { error in
            XCTAssertEqual(
                error as? TLSHandshakeMessageFramingError,
                .invalidMaximumMessageByteCount(3)
            )
        }
        XCTAssertThrowsError(
            try TLS13HandshakeMessageFramer(
                maximumMessageByteCount:
                    TLS13HandshakeMessageFramer.protocolMaximumMessageByteCount + 1
            )
        ) { error in
            XCTAssertEqual(
                error as? TLSHandshakeMessageFramingError,
                .invalidMaximumMessageByteCount(
                    TLS13HandshakeMessageFramer.protocolMaximumMessageByteCount + 1
                )
            )
        }
    }
}
