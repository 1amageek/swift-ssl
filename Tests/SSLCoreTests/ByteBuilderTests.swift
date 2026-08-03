import XCTest
import SSLCore

final class ByteBuilderTests: XCTestCase {
    func testEmitsContiguousOwner() throws {
        var builder = try ByteBuilder(maximumByteCount: 7, minimumCapacity: 7)
        try builder.appendUInt16BigEndian(0x1234)
        try builder.appendUInt24BigEndian(0x56789A)
        try builder.appendUInt16BigEndian(0xBCDE)
        let bytes = builder.finish()

        XCTAssertEqual(bytes.span[0], 0x12)
        XCTAssertEqual(bytes.span[6], 0xDE)
    }

    func testCapacityFailureIsTransactional() throws {
        var builder = try ByteBuilder(maximumByteCount: 2)
        try builder.append(0xAA)
        let source: ContiguousArray<UInt8> = [0xBB, 0xCC]

        XCTAssertThrowsError(try builder.append(source.span)) { error in
            XCTAssertEqual(
                error as? ByteError,
                .capacityExceeded(limit: 2, attempted: 3)
            )
        }

        XCTAssertEqual(builder.count, 1)
    }

    func testUInt24OverflowIsTypedAcrossPointerWidths() throws {
        var builder = try ByteBuilder(maximumByteCount: 3)

        XCTAssertThrowsError(try builder.appendUInt24BigEndian(UInt32.max)) { error in
            XCTAssertEqual(
                error as? ByteError,
                .integerDoesNotFit(value: UInt64(UInt32.max), byteCount: 3)
            )
        }
        XCTAssertEqual(builder.count, 0)
    }
}
