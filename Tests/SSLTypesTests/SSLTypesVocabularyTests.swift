import XCTest
@testable import SSLTypes

final class SSLTypesVocabularyTests: XCTestCase {
    func testCipherSuiteIsProtocolVocabulary() {
        XCTAssertEqual(TLSCipherSuite(rawValue: 0x1301), .aes128GCM_SHA256)
        XCTAssertNil(TLSCipherSuite(rawValue: 0x0000))
    }

    func testApplicationProtocolOwnsAndBorrowsBytes() throws {
        let protocolValue = try TLSApplicationProtocol(bytes: [0x68, 0x33])
        XCTAssertEqual(protocolValue.byteCount, 2)

        let borrowed = protocolValue.withBytes { span in
            var result = ContiguousArray<UInt8>()
            result.reserveCapacity(span.count)
            var index = 0
            while index < span.count {
                result.append(span[index])
                index += 1
            }
            return result
        }
        XCTAssertEqual(borrowed, [0x68, 0x33])
    }

    func testApplicationProtocolRejectsEmptyAndOversizedValues() {
        XCTAssertThrowsError(try TLSApplicationProtocol(bytes: []))
        XCTAssertThrowsError(
            try TLSApplicationProtocol(
                bytes: ContiguousArray(repeating: 0, count: Int(UInt8.max) + 1)
            )
        )
    }

    func testServerNameUsesItsOwnLengthBoundary() throws {
        let name = try TLSServerName(bytes: [0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65])
        XCTAssertEqual(name.byteCount, 7)
    }
}
