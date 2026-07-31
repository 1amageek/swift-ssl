import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import XCTest

final class TLS13TranscriptTests: XCTestCase {
    func testTranscriptDigestMatchesSHA256() throws {
        var transcript = try TLS13Transcript(maximumByteCount: 8)
        let first = ContiguousArray<UInt8>([1, 2, 3])
        let second = ContiguousArray<UInt8>([4, 5])
        try transcript.append(first.span)
        try transcript.append(second.span)

        let digest = try transcript.digest(for: .aes128GCM_SHA256)
        var expected = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
        var output = expected.mutableSpan
        try SHA256.hash(ContiguousArray<UInt8>([1, 2, 3, 4, 5]).span, into: &output)
        XCTAssertEqual(copy(digest.span), Array(expected))
    }

    func testTranscriptLimitIsTransactional() throws {
        var transcript = try TLS13Transcript(maximumByteCount: 3)
        try transcript.append(ContiguousArray<UInt8>([1, 2]).span)

        do {
            try transcript.append(ContiguousArray<UInt8>([3, 4]).span)
            XCTFail("transcript accepted bytes beyond its configured limit")
        } catch {
            XCTAssertEqual(error, .transcriptTooLong(limit: 3, attempted: 4))
        }
        XCTAssertEqual(transcript.byteCount, 2)
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
