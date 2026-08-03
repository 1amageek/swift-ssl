import XCTest
import SSLASN1
import SSLCore

final class DERCursorTests: XCTestCase {
    func testParsesNestedDER() throws {
        let source: ContiguousArray<UInt8> = [0x30, 0x03, 0x02, 0x01, 0x05]
        var budget = try makeBudget(inputByteCount: source.count)
        var root = DERCursor(source.span)

        do {
            let sequence = try root.readElement(using: &budget)
            XCTAssertEqual(sequence.tag.tagClass, .universal)
            XCTAssertTrue(sequence.tag.isConstructed)
            XCTAssertEqual(sequence.tag.number, 16)
            XCTAssertEqual(sequence.contentBytes.count, 3)

            try budget.enterContainer()
            var contents = DERCursor(sequence.contentBytes)
            let integer = try contents.readElement(using: &budget)
            XCTAssertEqual(integer.tag.number, 2)
            XCTAssertEqual(integer.contentBytes.count, 1)
            XCTAssertEqual(integer.contentBytes[0], 5)
            try contents.requireFullyConsumed()
            try budget.leaveContainer()
        }

        try root.requireFullyConsumed()
    }

    func testRejectsIndefiniteLength() throws {
        let source: ContiguousArray<UInt8> = [0x30, 0x80, 0x00, 0x00]
        var budget = try makeBudget(inputByteCount: source.count)
        var cursor = DERCursor(source.span)

        do {
            _ = try cursor.readElement(using: &budget)
            XCTFail("Indefinite-length BER was accepted as DER")
        } catch {
            XCTAssertEqual(error as? DERError, .indefiniteLength(offset: 1))
        }
    }

    func testRejectsNonMinimalLength() throws {
        let source: ContiguousArray<UInt8> = [0x04, 0x81, 0x01, 0x00]
        var budget = try makeBudget(inputByteCount: source.count)
        var cursor = DERCursor(source.span)

        do {
            _ = try cursor.readElement(using: &budget)
            XCTFail("A nonminimal length was accepted")
        } catch {
            XCTAssertEqual(error as? DERError, .nonMinimalLength(offset: 1))
        }
    }

    func testRejectsTruncatedContent() throws {
        let source: ContiguousArray<UInt8> = [0x04, 0x02, 0xAA]
        var budget = try makeBudget(inputByteCount: source.count)
        var cursor = DERCursor(source.span)

        do {
            _ = try cursor.readElement(using: &budget)
            XCTFail("Truncated content was accepted")
        } catch {
            XCTAssertEqual(
                error as? DERError,
                .truncated(offset: 2, requested: 2, available: 1)
            )
        }
    }

    private func makeBudget(inputByteCount: Int) throws -> ParsingBudget {
        let limits = try ParsingLimits(
            maximumInputBytes: 1_024,
            maximumNestingDepth: 8,
            maximumElementCount: 32,
            maximumExtensionCount: 16,
            maximumOIDBytes: 64,
            maximumStringBytes: 512
        )
        return try ParsingBudget(limits: limits, inputByteCount: inputByteCount)
    }
}
