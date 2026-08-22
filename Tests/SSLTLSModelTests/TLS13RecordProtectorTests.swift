import XCTest
import SSLCore
import SSLCrypto
import SSLTLS

final class TLS13RecordProtectorTests: XCTestCase {
    func testRoundTripForAllTLS13SuitesAndPadding() throws {
        let plaintext: ContiguousArray<UInt8> = [0x68, 0x65, 0x6C, 0x6C, 0x6F]
        for suite in TLSCipherSuite.allCases {
            let secretCount = suite == .aes256GCM_SHA384 ? 48 : 32
            let secret = ContiguousArray<UInt8>(repeating: 0x42, count: secretCount)
            var sealProtector = try TLS13RecordProtector(
                cipherSuite: suite,
                trafficSecret: secret.span
            )
            var record = ContiguousArray<UInt8>(repeating: 0xA5, count: 256)
            try record.withUnsafeMutableBufferPointer { buffer in
                var recordSpan = MutableSpan(_unsafeStart: buffer.baseAddress!, count: buffer.count)
                try sealProtector.seal(
                    content: plaintext.span,
                    contentType: .applicationData,
                    paddingByteCount: 7,
                    into: &recordSpan
                )
            }
            let recordCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
            var openProtector = try TLS13RecordProtector(
                cipherSuite: suite,
                trafficSecret: secret.span
            )
            var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
            let type = try recovered.withUnsafeMutableBufferPointer { destination in
                var recoveredSpan = MutableSpan(_unsafeStart: destination.baseAddress!, count: destination.count)
                return try record.withUnsafeBufferPointer { buffer in
                    try openProtector.open(
                        record: Span(_unsafeElements: UnsafeBufferPointer(start: buffer.baseAddress, count: recordCount)),
                        into: &recoveredSpan
                    )
                }
            }
            XCTAssertEqual(type, .applicationData)
            XCTAssertEqual(Array(recovered), Array(plaintext))
        }
    }

    func testAuthenticationFailureDoesNotModifyOutput() throws {
        let secret = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
        var protector = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )
        let handshake = ContiguousArray<UInt8>([1, 2, 3])
        var record = ContiguousArray<UInt8>(repeating: 0, count: 128)
        try record.withUnsafeMutableBufferPointer { buffer in
            var recordSpan = MutableSpan(_unsafeStart: buffer.baseAddress!, count: buffer.count)
            try protector.seal(content: handshake.span, contentType: .handshake, into: &recordSpan)
        }
        let recordCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
        record[recordCount - 1] ^= 0x80
        var openProtector = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )
        var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: 3)
        let before = recovered
        XCTAssertThrowsError(try recovered.withUnsafeMutableBufferPointer { destination in
            var recoveredSpan = MutableSpan(_unsafeStart: destination.baseAddress!, count: destination.count)
            _ = try record.withUnsafeBufferPointer { buffer in
                try openProtector.open(
                    record: Span(_unsafeElements: UnsafeBufferPointer(start: buffer.baseAddress, count: recordCount)),
                    into: &recoveredSpan
                )
            }
        }) { error in
            XCTAssertEqual(error as? TLS13RecordError, .authenticationFailed)
        }
        XCTAssertEqual(recovered, before)
    }

    func testDirectOpenPublishesOnlyAuthenticatedContent() throws {
        let plaintext = ContiguousArray<UInt8>([0x10, 0x20, 0x30])
        for suite in TLSCipherSuite.allCases {
            let secretCount = suite == .aes256GCM_SHA384 ? 48 : 32
            let secret = ContiguousArray<UInt8>(repeating: 0x5A, count: secretCount)
            var sender = try TLS13RecordProtector(
                cipherSuite: suite,
                trafficSecret: secret.span
            )
            var record = ContiguousArray<UInt8>(repeating: 0, count: 128)
            try record.withUnsafeMutableBufferPointer { buffer in
                var destination = MutableSpan(
                    _unsafeStart: buffer.baseAddress!,
                    count: buffer.count
                )
                try sender.seal(
                    content: plaintext.span,
                    contentType: .applicationData,
                    paddingByteCount: 5,
                    into: &destination
                )
            }
            let recordByteCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
            let innerByteCount = recordByteCount - 5 - 16
            var receiver = try TLS13RecordProtector(
                cipherSuite: suite,
                trafficSecret: secret.span
            )
            var opened = ContiguousArray<UInt8>(repeating: 0xA5, count: innerByteCount)
            let contentType = try opened.withUnsafeMutableBufferPointer { output in
                var destination = MutableSpan(
                    _unsafeStart: output.baseAddress!,
                    count: output.count
                )
                return try record.withUnsafeBufferPointer { input in
                    try receiver.openUnpublished(
                        record: Span(
                            _unsafeElements: UnsafeBufferPointer(
                                start: input.baseAddress,
                                count: recordByteCount
                            )
                        ),
                        into: &destination
                    )
                }
            }

            XCTAssertEqual(contentType, .applicationData)
            XCTAssertEqual(receiver.lastOpenedByteCount, plaintext.count)
            XCTAssertEqual(Array(opened.prefix(plaintext.count)), Array(plaintext))
            XCTAssertTrue(opened.dropFirst(plaintext.count).allSatisfy { $0 == 0 })
            XCTAssertEqual(receiver.currentSequenceNumber, 1)
        }
    }

    func testDirectOpenRejectsAliasingWithoutConsumingSequence() throws {
        let secret = ContiguousArray<UInt8>(repeating: 0x27, count: 32)
        let plaintext = ContiguousArray<UInt8>([0x41, 0x42, 0x43])
        var sender = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )
        var record = ContiguousArray<UInt8>(repeating: 0, count: 128)
        try record.withUnsafeMutableBufferPointer { buffer in
            var destination = MutableSpan(
                _unsafeStart: buffer.baseAddress!,
                count: buffer.count
            )
            try sender.seal(
                content: plaintext.span,
                contentType: .applicationData,
                into: &destination
            )
        }
        let recordByteCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
        let innerByteCount = recordByteCount - 5 - 16
        var aliased = ContiguousArray(record.prefix(recordByteCount))
        let before = aliased
        var receiver = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )

        XCTAssertThrowsError(try aliased.withUnsafeMutableBufferPointer { buffer in
            let input = Span(
                _unsafeElements: UnsafeBufferPointer(
                    start: buffer.baseAddress,
                    count: buffer.count
                )
            )
            var destination = MutableSpan(
                _unsafeStart: buffer.baseAddress!,
                count: innerByteCount
            )
            _ = try receiver.openUnpublished(
                record: input,
                into: &destination
            )
        }) { error in
            XCTAssertEqual(error as? TLS13RecordError, .overlappingInputAndOutput)
        }
        XCTAssertEqual(aliased, before)
        XCTAssertEqual(receiver.currentSequenceNumber, 0)
        XCTAssertEqual(receiver.lastOpenedByteCount, 0)

        var opened = ContiguousArray<UInt8>(repeating: 0, count: innerByteCount)
        _ = try opened.withUnsafeMutableBufferPointer { output in
            var destination = MutableSpan(
                _unsafeStart: output.baseAddress!,
                count: output.count
            )
            return try before.withUnsafeBufferPointer { input in
                try receiver.openUnpublished(
                    record: Span(_unsafeElements: input),
                    into: &destination
                )
            }
        }
        XCTAssertEqual(Array(opened.prefix(plaintext.count)), Array(plaintext))
        XCTAssertEqual(receiver.currentSequenceNumber, 1)
    }

    func testDirectOpenFailureWipesDestinationAndPreservesSequence() throws {
        let secret = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
        let plaintext = ContiguousArray<UInt8>([0x01, 0x02, 0x03])
        var sender = try TLS13RecordProtector(
            cipherSuite: .chacha20Poly1305_SHA256,
            trafficSecret: secret.span
        )
        var record = ContiguousArray<UInt8>(repeating: 0, count: 128)
        try record.withUnsafeMutableBufferPointer { buffer in
            var destination = MutableSpan(
                _unsafeStart: buffer.baseAddress!,
                count: buffer.count
            )
            try sender.seal(
                content: plaintext.span,
                contentType: .applicationData,
                paddingByteCount: 3,
                into: &destination
            )
        }
        let recordByteCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
        let validRecord = record
        record[recordByteCount - 1] ^= 0x80
        let innerByteCount = recordByteCount - 5 - 16
        var receiver = try TLS13RecordProtector(
            cipherSuite: .chacha20Poly1305_SHA256,
            trafficSecret: secret.span
        )
        var opened = ContiguousArray<UInt8>(repeating: 0xA5, count: innerByteCount)

        XCTAssertThrowsError(try opened.withUnsafeMutableBufferPointer { output in
            var destination = MutableSpan(
                _unsafeStart: output.baseAddress!,
                count: output.count
            )
            _ = try record.withUnsafeBufferPointer { input in
                try receiver.openUnpublished(
                    record: Span(
                        _unsafeElements: UnsafeBufferPointer(
                            start: input.baseAddress,
                            count: recordByteCount
                        )
                    ),
                    into: &destination
                )
            }
        }) { error in
            XCTAssertEqual(error as? TLS13RecordError, .authenticationFailed)
        }
        XCTAssertEqual(opened, ContiguousArray(repeating: 0, count: innerByteCount))
        XCTAssertEqual(receiver.currentSequenceNumber, 0)
        XCTAssertEqual(receiver.lastOpenedByteCount, 0)

        let contentType = try opened.withUnsafeMutableBufferPointer { output in
            var destination = MutableSpan(
                _unsafeStart: output.baseAddress!,
                count: output.count
            )
            return try validRecord.withUnsafeBufferPointer { input in
                try receiver.openUnpublished(
                    record: Span(
                        _unsafeElements: UnsafeBufferPointer(
                            start: input.baseAddress,
                            count: recordByteCount
                        )
                    ),
                    into: &destination
                )
            }
        }
        XCTAssertEqual(contentType, .applicationData)
        XCTAssertEqual(receiver.currentSequenceNumber, 1)
    }

    func testCompatibilityOutputTooSmallDoesNotConsumeRecordSequence() throws {
        let secret = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
        let plaintext = ContiguousArray<UInt8>([0xAA, 0xBB, 0xCC])
        var sender = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )
        var record = ContiguousArray<UInt8>(repeating: 0, count: 128)
        try record.withUnsafeMutableBufferPointer { buffer in
            var destination = MutableSpan(
                _unsafeStart: buffer.baseAddress!,
                count: buffer.count
            )
            try sender.seal(
                content: plaintext.span,
                contentType: .applicationData,
                paddingByteCount: 7,
                into: &destination
            )
        }
        let recordByteCount = 5 + ((Int(record[3]) << 8) | Int(record[4]))
        var receiver = try TLS13RecordProtector(
            cipherSuite: .aes128GCM_SHA256,
            trafficSecret: secret.span
        )
        var undersized = ContiguousArray<UInt8>(repeating: 0xA5, count: 2)

        XCTAssertThrowsError(try undersized.withUnsafeMutableBufferPointer { output in
            var destination = MutableSpan(
                _unsafeStart: output.baseAddress!,
                count: output.count
            )
            _ = try record.withUnsafeBufferPointer { input in
                try receiver.open(
                    record: Span(
                        _unsafeElements: UnsafeBufferPointer(
                            start: input.baseAddress,
                            count: recordByteCount
                        )
                    ),
                    into: &destination
                )
            }
        }) { error in
            XCTAssertEqual(
                error as? TLS13RecordError,
                .outputTooSmall(required: plaintext.count, actual: 2)
            )
        }
        XCTAssertEqual(receiver.currentSequenceNumber, 0)
        XCTAssertEqual(receiver.lastOpenedByteCount, 0)

        var opened = ContiguousArray<UInt8>(repeating: 0, count: plaintext.count)
        _ = try opened.withUnsafeMutableBufferPointer { output in
            var destination = MutableSpan(
                _unsafeStart: output.baseAddress!,
                count: output.count
            )
            return try record.withUnsafeBufferPointer { input in
                try receiver.open(
                    record: Span(
                        _unsafeElements: UnsafeBufferPointer(
                            start: input.baseAddress,
                            count: recordByteCount
                        )
                    ),
                    into: &destination
                )
            }
        }
        XCTAssertEqual(opened, plaintext)
        XCTAssertEqual(receiver.currentSequenceNumber, 1)
    }
}
