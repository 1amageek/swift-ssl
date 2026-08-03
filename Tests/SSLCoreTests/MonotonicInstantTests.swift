import XCTest
import SSLCore

final class MonotonicInstantTests: XCTestCase {
    func testComputesDistanceWithinOneClockDomain() throws {
        let earlier = try MonotonicInstant(
            clockIdentifier: 1,
            ticks: 10,
            ticksPerSecond: 1_000
        )
        let later = try MonotonicInstant(
            clockIdentifier: 1,
            ticks: 25,
            ticksPerSecond: 1_000
        )

        XCTAssertEqual(try later.tickDistance(since: earlier), 15)
    }

    func testRejectsDifferentClockDomains() throws {
        let first = try MonotonicInstant(
            clockIdentifier: 1,
            ticks: 10,
            ticksPerSecond: 1_000
        )
        let second = try MonotonicInstant(
            clockIdentifier: 2,
            ticks: 20,
            ticksPerSecond: 1_000
        )

        XCTAssertThrowsError(try second.tickDistance(since: first)) { error in
            XCTAssertEqual(
                error as? ClockError,
                .clockDomainMismatch(expected: 2, actual: 1)
            )
        }
    }

    func testRejectsClockRegression() throws {
        let earlier = try MonotonicInstant(
            clockIdentifier: 1,
            ticks: 20,
            ticksPerSecond: 1_000
        )
        let later = try MonotonicInstant(
            clockIdentifier: 1,
            ticks: 10,
            ticksPerSecond: 1_000
        )

        XCTAssertThrowsError(try later.tickDistance(since: earlier)) { error in
            XCTAssertEqual(error as? ClockError, .movedBackwards)
        }
    }
}
