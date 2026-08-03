import XCTest
import SSLCore

final class OwnedBytesTests: XCTestCase {
    func testCopyingCreatesIndependentOwner() throws {
        var source: ContiguousArray<UInt8> = [1, 2, 3, 4]
        let owned = OwnedBytes(copying: source.span)
        source[0] = 9

        XCTAssertEqual(owned.count, 4)
        XCTAssertEqual(owned[0], 1)
        XCTAssertEqual(owned.span[3], 4)
    }

    func testCheckedRanges() throws {
        let source: ContiguousArray<UInt8> = [10, 11, 12, 13]
        let owned = OwnedBytes(copying: source.span)
        let validRange = try ByteRange(offset: 1, count: 2)
        let valid = try owned.span(in: validRange)

        XCTAssertEqual(valid.count, 2)
        XCTAssertEqual(valid[0], 11)
        XCTAssertEqual(valid[1], 12)

        let invalidRange = try ByteRange(offset: 3, count: 2)
        do {
            _ = try owned.span(in: invalidRange)
            XCTFail("An out-of-bounds range was accepted")
        } catch {
            XCTAssertEqual(
                error as? ByteError,
                .outOfBounds(offset: 3, requested: 2, available: 1)
            )
        }
    }
}
