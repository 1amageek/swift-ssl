import XCTest
import SSLCore

final class TLSBufferContractTests: XCTestCase {
    func testInputBorrowsValidatedRangeWithoutExposingStorage() throws {
        let source: ContiguousArray<UInt8> = [1, 2, 3, 4, 5]
        let input = TLSInput(copying: source.span)
        let range = try TLSBufferRange(offset: 1, count: 3)

        try input.withBorrowedBytes(in: range) { bytes in
            XCTAssertEqual(bytes.count, 3)
            XCTAssertEqual(bytes[0], 2)
            XCTAssertEqual(bytes[1], 3)
            XCTAssertEqual(bytes[2], 4)
        }
    }

    func testOutputSinkReportsCapacityWithoutTruncation() throws {
        var sink = try ContiguousTLSOutputSink(maximumByteCount: 2)
        let source: ContiguousArray<UInt8> = [0xAA, 0xBB, 0xCC]

        XCTAssertThrowsError(try sink.write(source.span)) { error in
            XCTAssertEqual(
                error as? TLSOutputSinkError,
                .insufficientCapacity(required: 3, available: 2)
            )
        }

        XCTAssertEqual(sink.remainingCapacity, 2)
        let result = sink.finish()
        XCTAssertTrue(result.isEmpty)
    }

    func testOutputSinkReportsAdditionalCapacityAfterAWrite() throws {
        var sink = try ContiguousTLSOutputSink(maximumByteCount: 3)
        let first: ContiguousArray<UInt8> = [0xAA]
        let second: ContiguousArray<UInt8> = [0xBB, 0xCC, 0xDD]
        try sink.write(first.span)

        XCTAssertThrowsError(try sink.write(second.span)) { error in
            XCTAssertEqual(
                error as? TLSOutputSinkError,
                .insufficientCapacity(required: 3, available: 2)
            )
        }

        XCTAssertEqual(sink.remainingCapacity, 2)
    }
}
