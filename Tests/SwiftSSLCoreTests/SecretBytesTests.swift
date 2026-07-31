import XCTest
@testable import SwiftSSLCore

final class SecretBytesTests: XCTestCase {
    private enum InitializationFailure: Error, Equatable {
        case intentional
    }

    func testDirectInitialization() throws {
        let byteCount = try SecretByteCount(4)
        let secret = SecretBytes(byteCount: byteCount) { destination in
            destination[0] = 1
            destination[1] = 2
            destination[2] = 3
            destination[3] = 4
        }

        secret.withBorrowedBytes { bytes in
            XCTAssertEqual(bytes.count, 4)
            XCTAssertEqual(bytes[0], 1)
            XCTAssertEqual(bytes[3], 4)
        }
    }

    func testFailedInitializationRethrows() throws {
        let byteCount = try SecretByteCount(4)

        do {
            let secret = try SecretBytes(byteCount: byteCount) { destination throws(InitializationFailure) in
                destination[0] = 0xAA
                throw .intentional
            }
            secret.withBorrowedBytes { _ in
                XCTFail("A failed secret initializer returned an owner")
            }
        } catch let error {
            XCTAssertEqual(error, .intentional)
        }
    }

    func testSecureWipeOverwritesRange() {
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 8)
        pointer.initialize(repeating: 0xA5, count: 8)
        defer {
            pointer.deinitialize(count: 8)
            pointer.deallocate()
        }

        SecureWipe.erase(UnsafeMutableRawPointer(pointer), byteCount: 8)

        for index in 0..<8 {
            XCTAssertEqual(pointer[index], 0)
        }
    }

    func testSecretByteCountRejectsOversizedAllocation() {
        XCTAssertThrowsError(
            try SecretByteCount(SecretByteCount.maximumSupportedByteCount + 1)
        ) { error in
            XCTAssertEqual(
                error as? SecretMemoryError,
                .byteCountExceedsLimit(
                    limit: SecretByteCount.maximumSupportedByteCount,
                    actual: SecretByteCount.maximumSupportedByteCount + 1
                )
            )
        }
    }
}
