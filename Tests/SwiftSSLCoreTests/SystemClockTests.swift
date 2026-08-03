import SwiftSSLCore
import XCTest

final class SystemClockTests: XCTestCase {
    func testWallClockReturnsCanonicalRealtimeInstant() throws {
        let instant = try SystemWallClock().now()

        XCTAssertGreaterThan(instant.secondsSinceUnixEpoch, 0)
        XCTAssertLessThan(instant.nanoseconds, 1_000_000_000)
    }

    func testMonotonicClockUsesOneStableDomain() throws {
        let first = try SystemMonotonicClock().now()
        let second = try SystemMonotonicClock().now()

        XCTAssertEqual(first.clockIdentifier, second.clockIdentifier)
        XCTAssertEqual(first.ticksPerSecond, 1_000_000_000)
        XCTAssertEqual(second.ticksPerSecond, 1_000_000_000)
        XCTAssertNoThrow(try second.tickDistance(since: first))
    }
}
