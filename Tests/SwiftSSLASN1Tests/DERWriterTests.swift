import XCTest
import SwiftSSLASN1
import SwiftSSLCore

final class DERWriterTests: XCTestCase {
    func testWritesCanonicalIntegerAndBoolean() throws {
        var writer = try DERWriter(maximumByteCount: 32)
        try writer.appendPositiveInteger(128)
        try writer.appendBoolean(true)

        let result = writer.finish()
        XCTAssertEqual(copy(result.span), [0x02, 0x02, 0x00, 0x80, 0x01, 0x01, 0xFF])
    }

    func testWritesLongFormLength() throws {
        let content = ContiguousArray<UInt8>(repeating: 0xA5, count: 128)
        var writer = try DERWriter(maximumByteCount: 131)
        try writer.append(
            tag: DERTag(tagClass: .universal, isConstructed: false, number: 4),
            content: content.span
        )
        let result = writer.finish()
        XCTAssertEqual(result.count, 131)
        XCTAssertEqual(result[0], 0x04)
        XCTAssertEqual(result[1], 0x81)
        XCTAssertEqual(result[2], 0x80)
        XCTAssertEqual(result[130], 0xA5)
    }

    func testCapacityFailureDoesNotReportSuccess() throws {
        var writer = try DERWriter(maximumByteCount: 3)
        XCTAssertThrowsError(try writer.appendPositiveInteger(128)) { error in
            XCTAssertEqual(
                error as? DERWriteError,
                .capacity(.capacityExceeded(limit: 3, attempted: 4))
            )
        }
        XCTAssertEqual(writer.count, 0)
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
