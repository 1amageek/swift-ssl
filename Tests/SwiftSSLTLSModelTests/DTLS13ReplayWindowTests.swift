import SwiftSSLTLS
import XCTest

final class DTLS13ReplayWindowTests: XCTestCase {
    func testAcceptsOutOfOrderPacketsAndRejectsReplay() throws {
        var window = DTLS13ReplayWindow()
        XCTAssertEqual(try window.accept(10), .accepted)
        XCTAssertEqual(try window.accept(8), .accepted)
        XCTAssertEqual(try window.accept(10), .replayed)
        XCTAssertTrue(try window.contains(8))
        XCTAssertFalse(try window.contains(9))
    }

    func testAdvancingBeyondWindowExpiresOldPackets() throws {
        var window = DTLS13ReplayWindow()
        XCTAssertEqual(try window.accept(1), .accepted)
        XCTAssertEqual(try window.accept(65), .accepted)
        XCTAssertEqual(try window.accept(1), .tooOld)
        XCTAssertEqual(try window.accept(2), .accepted)
    }

    func testRejectsSequenceNumberOutsideDTLSRange() {
        var window = DTLS13ReplayWindow()
        XCTAssertThrowsError(try window.accept(DTLS13ReplayWindow.maximumSequenceNumber + 1)) { error in
            XCTAssertEqual(
                error as? DTLS13ReplayError,
                .invalidSequenceNumber(DTLS13ReplayWindow.maximumSequenceNumber + 1)
            )
        }
    }
}
