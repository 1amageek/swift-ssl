import XCTest
import SSLASN1
import SSLCore

final class PEMCodecTests: XCTestCase {
    func testRoundTripUsesCanonicalBase64() throws {
        let der: ContiguousArray<UInt8> = [0x30, 0x03, 0x02, 0x01, 0x05]
        let block = try PEMBlock(label: "TEST DATA", der: OwnedBytes(consuming: der))
        let encoded = try PEMCodec.encode(block)
        XCTAssertEqual(
            String(decoding: copy(encoded.span), as: UTF8.self),
            "-----BEGIN TEST DATA-----\nMAMCAQU=\n-----END TEST DATA-----\n"
        )
        let decoded = try PEMCodec.decode(encoded.span)
        XCTAssertEqual(decoded.label, "TEST DATA")
        XCTAssertEqual(decoded.derByteCount, der.count)
        decoded.withDERBytes { bytes in
            XCTAssertEqual(copy(bytes), Array(der))
        }
    }

    func testDecodeAcceptsCRLFAndRejectsMalformedInput() throws {
        let crlf = ContiguousArray("-----BEGIN TEST-----\r\nAQID\r\n-----END TEST-----\r\n".utf8)
        let decoded = try PEMCodec.decode(crlf.span)
        decoded.withDERBytes { bytes in
            XCTAssertEqual(copy(bytes), [1, 2, 3])
        }

        let invalidPadding = ContiguousArray("-----BEGIN TEST-----\nAB=A\n-----END TEST-----\n".utf8)
        XCTAssertThrowsError(try PEMCodec.decode(invalidPadding.span)) { error in
            guard let typed = error as? PEMError, case .invalidBase64Padding = typed else {
                return XCTFail("unexpected error: \(error)")
            }
        }

        let mismatched = ContiguousArray("-----BEGIN TEST-----\nAQ==\n-----END OTHER-----\n".utf8)
        XCTAssertThrowsError(try PEMCodec.decode(mismatched.span)) { error in
            XCTAssertEqual(error as? PEMError, .boundaryLabelMismatch)
        }
    }

    func testLimitsAndTrailingDataAreFailures() throws {
        let source = ContiguousArray("-----BEGIN TEST-----\nAQID\n-----END TEST-----\n".utf8)
        XCTAssertThrowsError(try PEMCodec.decode(source.span, maximumDERByteCount: 2)) { error in
            guard let typed = error as? PEMError,
                  case let PEMError.outputLimitExceeded(limit, _) = typed else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(limit, 2)
        }

        let trailing = ContiguousArray("-----BEGIN TEST-----\nAQID\n-----END TEST-----\nextra".utf8)
        XCTAssertThrowsError(try PEMCodec.decode(trailing.span)) { error in
            guard let typed = error as? PEMError,
                  case let PEMError.trailingData(offset) = typed else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertGreaterThan(offset, 0)
        }
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
