import XCTest
import SwiftSSLCore

final class ParsingBudgetTests: XCTestCase {
    func testIndependentLimits() throws {
        let limits = try ParsingLimits(
            maximumInputBytes: 16,
            maximumNestingDepth: 1,
            maximumElementCount: 2,
            maximumExtensionCount: 1,
            maximumOIDBytes: 8,
            maximumStringBytes: 8
        )
        var budget = try ParsingBudget(limits: limits, inputByteCount: 8)

        try budget.consumeElement()
        try budget.consumeElement()
        XCTAssertThrowsError(try budget.consumeElement()) { error in
            XCTAssertEqual(error as? ResourceLimitError, .elementCount(limit: 2))
        }

        try budget.enterContainer()
        XCTAssertThrowsError(try budget.enterContainer()) { error in
            XCTAssertEqual(error as? ResourceLimitError, .nestingDepth(limit: 1))
        }
        try budget.leaveContainer()
    }

    func testRejectsUnbalancedContainerExit() throws {
        let limits = try ParsingLimits(
            maximumInputBytes: 16,
            maximumNestingDepth: 1,
            maximumElementCount: 2,
            maximumExtensionCount: 1,
            maximumOIDBytes: 8,
            maximumStringBytes: 8
        )
        var budget = try ParsingBudget(limits: limits, inputByteCount: 0)

        XCTAssertThrowsError(try budget.leaveContainer()) { error in
            XCTAssertEqual(error as? ResourceLimitError, .unbalancedNesting)
        }
    }

    func testRejectsNegativeDerivedByteCounts() throws {
        let limits = try ParsingLimits(
            maximumInputBytes: 16,
            maximumNestingDepth: 1,
            maximumElementCount: 2,
            maximumExtensionCount: 1,
            maximumOIDBytes: 8,
            maximumStringBytes: 8
        )
        let budget = try ParsingBudget(limits: limits, inputByteCount: 0)

        XCTAssertThrowsError(try budget.requireOIDByteCount(-1)) { error in
            XCTAssertEqual(
                error as? ResourceLimitError,
                .invalidLimit(name: "oidByteCount", value: -1)
            )
        }
        XCTAssertThrowsError(try budget.requireStringByteCount(-1)) { error in
            XCTAssertEqual(
                error as? ResourceLimitError,
                .invalidLimit(name: "stringByteCount", value: -1)
            )
        }
    }
}
