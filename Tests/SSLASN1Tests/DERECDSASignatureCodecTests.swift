import XCTest
import SSLASN1
import SSLCore

final class DERECDSASignatureCodecTests: XCTestCase {
    func testRoundTripPreservesFixedWidthScalars() throws {
        var raw = ContiguousArray<UInt8>(repeating: 0, count: 64)
        raw[31] = 0x80
        raw[32] = 0x80
        raw[63] = 0x01

        let encoded = try DERECDSASignatureCodec.encode(
            rawSignature: raw.span,
            scalarByteCount: 32
        )
        let decoded = try DERECDSASignatureCodec.decode(
            derSignature: encoded.span,
            scalarByteCount: 32
        )

        XCTAssertEqual(decoded, OwnedBytes(consuming: raw))
    }

    func testDecodeRejectsNegativeInteger() throws {
        let malformed: ContiguousArray<UInt8> = [
            0x30, 0x06,
            0x02, 0x01, 0x80,
            0x02, 0x01, 0x01,
        ]

        XCTAssertThrowsError(
            try DERECDSASignatureCodec.decode(
                derSignature: malformed.span,
                scalarByteCount: 32
            )
        ) { error in
            XCTAssertEqual(error as? DERECDSASignatureError, .invalidInteger)
        }
    }

    func testDecodeRejectsNonMinimalInteger() throws {
        let malformed: ContiguousArray<UInt8> = [
            0x30, 0x07,
            0x02, 0x02, 0x00, 0x01,
            0x02, 0x01, 0x01,
        ]

        XCTAssertThrowsError(
            try DERECDSASignatureCodec.decode(
                derSignature: malformed.span,
                scalarByteCount: 32
            )
        ) { error in
            XCTAssertEqual(error as? DERECDSASignatureError, .invalidInteger)
        }
    }

    func testDecodeRejectsTrailingData() throws {
        let malformed: ContiguousArray<UInt8> = [
            0x30, 0x06,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x00,
        ]

        XCTAssertThrowsError(
            try DERECDSASignatureCodec.decode(
                derSignature: malformed.span,
                scalarByteCount: 32
            )
        )
    }
}
