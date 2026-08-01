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

    func testEntropyInitializesOwnedSecretDirectly() throws {
        let byteCount = try SecretByteCount(64)
        let secret = try SecretBytes(
            randomByteCount: byteCount,
            using: RepeatingEntropy(byte: 0xA7)
        )

        secret.withBorrowedBytes { bytes in
            XCTAssertEqual(bytes.count, 64)
            for index in 0..<bytes.count {
                XCTAssertEqual(bytes[index], 0xA7)
            }
        }
    }

    func testEntropyFailureDoesNotReturnAnOwner() throws {
        let byteCount = try SecretByteCount(32)

        do {
            let secret = try SecretBytes(
                randomByteCount: byteCount,
                using: FailingEntropy()
            )
            secret.withBorrowedBytes { _ in
                XCTFail("A failed entropy source returned a secret owner")
            }
        } catch {
            XCTAssertEqual(error, .sourceRejected)
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

    func testSecureWipeOverwritesUInt16Words() {
        let pointer = UnsafeMutablePointer<UInt16>.allocate(capacity: 8)
        pointer.initialize(repeating: .max, count: 8)
        defer {
            pointer.deinitialize(count: 8)
            pointer.deallocate()
        }

        SecureWipe.eraseUInt16Words(pointer, wordCount: 8)

        for index in 0..<8 {
            XCTAssertEqual(pointer[index], 0)
        }
    }

    func testSecureWipeOverwritesUInt32Words() {
        let pointer = UnsafeMutablePointer<UInt32>.allocate(capacity: 8)
        pointer.initialize(repeating: .max, count: 8)
        defer {
            pointer.deinitialize(count: 8)
            pointer.deallocate()
        }

        SecureWipe.eraseUInt32Words(pointer, wordCount: 8)

        for index in 0..<8 {
            XCTAssertEqual(pointer[index], 0)
        }
    }

    func testSecureWipeOverwritesUInt64Words() {
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: 8 * MemoryLayout<UInt64>.stride,
            alignment: MemoryLayout<UInt64>.alignment
        )
        pointer.initializeMemory(as: UInt64.self, repeating: .max, count: 8)
        defer {
            pointer.assumingMemoryBound(to: UInt64.self).deinitialize(count: 8)
            pointer.deallocate()
        }

        SecureWipe.eraseUInt64Words(pointer, wordCount: 8)

        let words = UnsafeBufferPointer(
            start: UnsafePointer(pointer.assumingMemoryBound(to: UInt64.self)),
            count: 8
        )
        for word in words {
            XCTAssertEqual(word, 0)
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

    private struct RepeatingEntropy: EntropySource {
        let byte: UInt8

        func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
            var index = 0
            while index < destination.count {
                destination[index] = byte
                index += 1
            }
        }
    }

    private struct FailingEntropy: EntropySource {
        func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
            if !destination.isEmpty {
                destination[0] = 0xA7
            }
            throw .sourceRejected
        }
    }
}
