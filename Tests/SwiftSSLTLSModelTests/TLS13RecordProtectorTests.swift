import XCTest
import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

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
            try record.withUnsafeBufferPointer { buffer in
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
}
