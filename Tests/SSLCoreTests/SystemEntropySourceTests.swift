import SSLCore
import XCTest

final class SystemEntropySourceTests: XCTestCase {
    func testFillsRequestedBytes() throws {
        let source = SystemEntropySource()
        var bytes = ContiguousArray<UInt8>(repeating: 0, count: 64)
        var destination = bytes.mutableSpan
        try source.fill(&destination)

        XCTAssertTrue(bytes.contains { $0 != 0 })
    }

    func testRejectsOversizedRequestWithoutMutation() {
        let source = SystemEntropySource()
        var bytes = ContiguousArray<UInt8>(repeating: 0xA5, count: SystemEntropySource.maximumRequestByteCount + 1)
        let original = bytes
        var destination = bytes.mutableSpan

        do {
            try source.fill(&destination)
            XCTFail("oversized entropy request was accepted")
        } catch {
            XCTAssertEqual(error, .requestTooLarge(
                limit: SystemEntropySource.maximumRequestByteCount,
                requested: SystemEntropySource.maximumRequestByteCount + 1
            ))
        }
        XCTAssertEqual(bytes, original)
    }
}
