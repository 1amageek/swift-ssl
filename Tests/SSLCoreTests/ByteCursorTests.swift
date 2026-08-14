import XCTest
import SSLCore

final class ByteCursorTests: XCTestCase {
    func testReadsValuesAndSpans() throws {
        let source: ContiguousArray<UInt8> = [0x12, 0x34, 0x56, 0x78, 0x9A]
        var cursor = ByteCursor(source.span)

        XCTAssertEqual(try cursor.readUInt16BigEndian(), 0x1234)
        let middle = try cursor.readSpan(count: 2)
        XCTAssertEqual(middle[0], 0x56)
        XCTAssertEqual(middle[1], 0x78)
        XCTAssertEqual(try cursor.readByte(), 0x9A)
        XCTAssertNoThrow(try cursor.requireFullyConsumed())
    }

    func testFailedReadIsTransactional() throws {
        let source: ContiguousArray<UInt8> = [1, 2]
        var cursor = ByteCursor(source.span)

        do {
            _ = try cursor.readSpan(count: 3)
            XCTFail("A truncated read succeeded")
        } catch {
            XCTAssertEqual(
                error,
                .outOfBounds(offset: 0, requested: 3, available: 2)
            )
        }

        XCTAssertEqual(cursor.offset, 0)
        XCTAssertEqual(try cursor.readUInt16BigEndian(), 0x0102)
    }

    func testTruncatedIntegerReadIsTransactional() throws {
        let source: ContiguousArray<UInt8> = [0x12, 0x34, 0x56]
        var cursor = ByteCursor(source.span)

        XCTAssertThrowsError(try cursor.readUInt32BigEndian()) { error in
            XCTAssertEqual(
                error as? ByteError,
                .outOfBounds(offset: 0, requested: 4, available: 3)
            )
        }

        XCTAssertEqual(cursor.offset, 0)
        XCTAssertEqual(try cursor.readUInt24BigEndian(), 0x123456)
    }
}
