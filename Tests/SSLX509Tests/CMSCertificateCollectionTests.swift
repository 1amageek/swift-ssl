import XCTest
import SSLCore
import SSLX509

final class CMSCertificateCollectionTests: XCTestCase {
    func testEncodesParsesAndBorrowsCertificateDER() throws {
        let certificateDER = makeCertificate(signatureByte: 0x02)
        let collection = try CMSCertificateCollection(
            certificates: [CertificateBytes(copying: certificateDER.span)]
        )
        XCTAssertEqual(collection.certificateCount, 1)

        var encoded = ContiguousArray<UInt8>()
        collection.withDERBytes { bytes in
            encoded = copy(bytes)
        }
        let reparsed = try CMSCertificateCollection(der: encoded.span)
        var recovered = ContiguousArray<UInt8>()
        try reparsed.withCertificateDER(at: 0) { bytes in
            recovered = copy(bytes)
        }
        XCTAssertEqual(recovered, certificateDER)
        XCTAssertNoThrow(try X509Certificate(der: recovered.span))
    }

    func testEncoderUsesCanonicalCertificateSetOrder() throws {
        let first = makeCertificate(signatureByte: 0x02)
        let second = makeCertificate(signatureByte: 0x03)
        let collection = try CMSCertificateCollection(
            certificates: [
                CertificateBytes(copying: second.span),
                CertificateBytes(copying: first.span),
            ]
        )

        var recoveredFirst = ContiguousArray<UInt8>()
        var recoveredSecond = ContiguousArray<UInt8>()
        try collection.withCertificateDER(at: 0) { bytes in
            recoveredFirst = copy(bytes)
        }
        try collection.withCertificateDER(at: 1) { bytes in
            recoveredSecond = copy(bytes)
        }
        XCTAssertEqual(recoveredFirst, first)
        XCTAssertEqual(recoveredSecond, second)
    }

    func testRejectsUnsupportedOuterContentType() throws {
        let certificateDER = makeCertificate(signatureByte: 0x02)
        let collection = try CMSCertificateCollection(
            certificates: [CertificateBytes(copying: certificateDER.span)]
        )
        var encoded = ContiguousArray<UInt8>()
        collection.withDERBytes { bytes in
            encoded = copy(bytes)
        }
        let signedDataOID: [UInt8] = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x07, 0x02,
        ]
        let offset = try XCTUnwrap(firstOffset(of: signedDataOID, in: encoded))
        encoded[offset + signedDataOID.count - 1] = 0x03

        do {
            _ = try CMSCertificateCollection(der: encoded.span)
            XCTFail("an unsupported CMS content type was accepted")
        } catch {
            XCTAssertEqual(
                error as? CMSCertificateCollectionError,
                .unsupportedContentType
            )
        }
    }

    func testRejectsEmptyCollectionAndOutOfBoundsAccess() throws {
        do {
            _ = try CMSCertificateCollection(certificates: [])
            XCTFail("an empty certificate collection was accepted")
        } catch {
            XCTAssertEqual(
                error as? CMSCertificateCollectionError,
                .emptyCertificateCollection
            )
        }

        let certificateDER = makeCertificate(signatureByte: 0x02)
        let collection = try CMSCertificateCollection(
            certificates: [CertificateBytes(copying: certificateDER.span)]
        )
        do {
            try collection.withCertificateDER(at: 1) { _ in () }
            XCTFail("an invalid certificate index was accepted")
        } catch {
            XCTAssertEqual(
                error as? CMSCertificateCollectionError,
                .certificateIndexOutOfBounds(index: 1, count: 1)
            )
        }
    }

    private func makeCertificate(
        signatureByte: UInt8
    ) -> ContiguousArray<UInt8> {
        var tbs: ContiguousArray<UInt8> = [
            0x30, 0x5A,
            0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x30, 0x00,
            0x30, 0x1E,
            0x17, 0x0D,
        ]
        tbs.append(contentsOf: ContiguousArray("240101000000Z".utf8))
        tbs.append(contentsOf: [0x17, 0x0D])
        tbs.append(contentsOf: ContiguousArray("250101000000Z".utf8))
        tbs.append(contentsOf: [
            0x30, 0x00,
            0x30, 0x2A,
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
            0x03, 0x21, 0x00,
        ])
        tbs.append(contentsOf: repeatElement(0xA5, count: 32))

        var result: ContiguousArray<UInt8> = [0x30, 0x68]
        result.append(contentsOf: tbs)
        result.append(contentsOf: [
            0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
            0x03, 0x03, 0x00, 0x01, signatureByte,
        ])
        return result
    }

    private func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }

    private func firstOffset(
        of needle: [UInt8],
        in haystack: ContiguousArray<UInt8>
    ) -> Int? {
        guard !needle.isEmpty, needle.count <= haystack.count else {
            return nil
        }
        var offset = 0
        while offset <= haystack.count - needle.count {
            var index = 0
            while index < needle.count,
                  haystack[offset + index] == needle[index] {
                index += 1
            }
            if index == needle.count {
                return offset
            }
            offset += 1
        }
        return nil
    }
}
