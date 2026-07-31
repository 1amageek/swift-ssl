import XCTest
import SwiftSSLCore
import SwiftSSLQUIC
import SwiftSSLTLS

final class TLSActionBatchTests: XCTestCase {
    func testValidatesActionRanges() throws {
        let source: ContiguousArray<UInt8> = [1, 2, 3, 4]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 1, count: 2)
        let actions: ContiguousArray<TLSStreamAction> = [
            .emitRecordBytes(range),
            .handshakeComplete,
        ]

        let batch = try TLSStreamActionBatch(bytes: bytes, actions: actions)
        XCTAssertEqual(batch.actions.count, 2)
        XCTAssertEqual(batch.bytes.count, 4)
    }

    func testRejectsInvalidRange() throws {
        let source: ContiguousArray<UInt8> = [1, 2]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 1, count: 2)
        let actions: ContiguousArray<TLSStreamAction> = [
            .emitRecordBytes(range)
        ]

        XCTAssertThrowsError(
            try TLSStreamActionBatch(bytes: bytes, actions: actions)
        ) { error in
            XCTAssertEqual(
                error as? ByteError,
                .outOfBounds(offset: 1, requested: 2, available: 1)
            )
        }
    }

    func testProfilesAreSemanticallyDistinct() {
        XCTAssertTrue(TLSStream13Profile.usesTLSRecords)
        XCTAssertFalse(TLSStream13Profile.usesDatagramReliability)
        XCTAssertFalse(DTLS13Profile.usesTLSRecords)
        XCTAssertTrue(DTLS13Profile.usesDatagramReliability)
        XCTAssertFalse(QUICTLSProfile.usesTLSRecords)
        XCTAssertFalse(QUICTLSProfile.usesDatagramReliability)
    }

    func testDTLSBatchValidatesDatagramRange() throws {
        let source: ContiguousArray<UInt8> = [1, 2, 3]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 0, count: 3)
        let actions: ContiguousArray<DTLSAction> = [
            .emitDatagram(range),
            .flushFlight,
        ]

        let batch = try DTLSActionBatch(bytes: bytes, actions: actions)
        XCTAssertEqual(batch.actions.count, 2)
    }

    func testDTLSBatchRejectsInvalidApplicationRange() throws {
        let source: ContiguousArray<UInt8> = [1, 2]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 1, count: 2)
        let actions: ContiguousArray<DTLSAction> = [
            .deliverApplicationData(bytes: range, isEarlyData: false)
        ]

        XCTAssertThrowsError(
            try DTLSActionBatch(bytes: bytes, actions: actions)
        ) { error in
            XCTAssertEqual(
                error as? ByteError,
                .outOfBounds(offset: 1, requested: 2, available: 1)
            )
        }
    }

    func testQUICActionOnlyReferencesHandshakeBytes() throws {
        let source: ContiguousArray<UInt8> = [1, 2, 3]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 0, count: 3)
        let actions: ContiguousArray<QUICTLSAction> = [
            .emitHandshakeBytes(level: .handshake, bytes: range),
            .handshakeComplete,
        ]

        let batch = try QUICTLSActionBatch(bytes: bytes, actions: actions)
        XCTAssertEqual(batch.actions.count, 2)
    }

    func testQUICBatchRejectsInvalidHandshakeRange() throws {
        let source: ContiguousArray<UInt8> = [1, 2]
        let bytes = OwnedBytes(copying: source.span)
        let range = try ByteRange(offset: 1, count: 2)
        let actions: ContiguousArray<QUICTLSAction> = [
            .emitHandshakeBytes(level: .initial, bytes: range)
        ]

        XCTAssertThrowsError(
            try QUICTLSActionBatch(bytes: bytes, actions: actions)
        ) { error in
            XCTAssertEqual(
                error as? ByteError,
                .outOfBounds(offset: 1, requested: 2, available: 1)
            )
        }
    }

    func testQUICSecretEventUsesScopedNoncopyableOwner() throws {
        let byteCount = try SecretByteCount(4)
        let secret = SecretBytes(byteCount: byteCount) { destination in
            destination[0] = 1
            destination[1] = 2
            destination[2] = 3
            destination[3] = 4
        }
        let event = QUICTrafficSecretEvent(
            direction: .write,
            level: .handshake,
            cipherSuite: .aes128GCM_SHA256,
            secret: secret
        )

        let sum = event.withBorrowedSecret { bytes in
            bytes[0] + bytes[1] + bytes[2] + bytes[3]
        }
        XCTAssertEqual(sum, 10)
        XCTAssertEqual(event.direction, .write)
        XCTAssertEqual(event.level, .handshake)
    }
}
