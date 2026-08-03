import XCTest
import SSLASN1
import SSLCore

final class DERPrimitiveCodecTests: XCTestCase {
    func testPrimitiveDecoders() throws {
        try withElement([0x02, 0x02, 0x00, 0x80]) { element in
            XCTAssertEqual(try DERPrimitiveCodec.decodePositiveInteger(from: element), 128)
        }
        try withElement([0x01, 0x01, 0xFF]) { element in
            XCTAssertTrue(try DERPrimitiveCodec.decodeBoolean(from: element))
        }
        try withElement([0x03, 0x02, 0x03, 0xA0]) { element in
            let decodedBits = try DERPrimitiveCodec.decodeBitString(from: element)
            XCTAssertEqual(decodedBits.unusedBitCount, 3)
            XCTAssertEqual(copy(decodedBits.bytes.span), [0xA0])
        }
        try withElement([0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]) { element in
            XCTAssertEqual(
                try DERPrimitiveCodec.decodeObjectIdentifier(from: element),
                [1, 2, 840, 113549]
            )
        }
    }

    func testPrimitiveDecodersRejectNonCanonicalValues() throws {
        try withElement([0x02, 0x02, 0x00, 0x01]) { element in
            XCTAssertThrowsError(try DERPrimitiveCodec.decodePositiveInteger(from: element)) { error in
                XCTAssertEqual(error as? DERValueError, .nonCanonicalInteger)
            }
        }

        try withElement([0x01, 0x01, 0x01]) { element in
            XCTAssertThrowsError(try DERPrimitiveCodec.decodeBoolean(from: element)) { error in
                XCTAssertEqual(error as? DERValueError, .invalidBoolean)
            }
        }

        try withElement([0x03, 0x02, 0x01, 0x81]) { element in
            XCTAssertThrowsError(try DERPrimitiveCodec.decodeBitString(from: element)) { error in
                XCTAssertEqual(error as? DERValueError, .invalidBitString)
            }
        }
    }

    private func withElement(
        _ bytes: [UInt8],
        _ body: (DERElementView) throws -> Void
    ) throws {
        let source = ContiguousArray(bytes)
        let limits = try ParsingLimits(
            maximumInputBytes: 1_024,
            maximumNestingDepth: 8,
            maximumElementCount: 32,
            maximumExtensionCount: 16,
            maximumOIDBytes: 64,
            maximumStringBytes: 512
        )
        var budget = try ParsingBudget(limits: limits, inputByteCount: source.count)
        var cursor = DERCursor(source.span)
        try body(cursor.readElement(using: &budget))
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
