import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class TLS13HandshakeMessageTests: XCTestCase {
    func testClientHelloRoundTrip() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x11, count: 32)
        let keyShare = ContiguousArray<UInt8>(repeating: 0x22, count: 32)
        let message = try TLS13HandshakeCodec.makeClientHello(
            random: random.span,
            keyShare: keyShare.span
        )
        let parsed = try TLS13HandshakeCodec.parseClientHello(message.span)

        XCTAssertEqual(copy(parsed.random.span), Array(random))
        XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
    }

    func testServerHelloRoundTrip() throws {
        let random = ContiguousArray<UInt8>(repeating: 0x33, count: 32)
        let keyShare = ContiguousArray<UInt8>(repeating: 0x44, count: 32)
        let message = try TLS13HandshakeCodec.makeServerHello(
            random: random.span,
            keyShare: keyShare.span
        )
        let parsed = try TLS13HandshakeCodec.parseServerHello(message.span)

        XCTAssertEqual(parsed.cipherSuite, .aes128GCM_SHA256)
        XCTAssertEqual(copy(parsed.random.span), Array(random))
        XCTAssertEqual(copy(parsed.keyShare.span), Array(keyShare))
    }

    func testCertificateAndFinishedMessagesHaveStrictLengths() throws {
        let certificate = ContiguousArray<UInt8>([1, 2, 3, 4])
        let certificateMessage = try TLS13HandshakeCodec.makeCertificate(certificateDER: certificate.span)
        let parsedCertificate = try TLS13HandshakeCodec.parseCertificate(certificateMessage.span)
        XCTAssertEqual(copy(parsedCertificate.span), Array(certificate))

        let verifyData = ContiguousArray<UInt8>(repeating: 0xA5, count: 32)
        let finished = try TLS13HandshakeCodec.makeFinished(verifyData: verifyData.span)
        let parsedFinished = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 32)
        XCTAssertEqual(copy(parsedFinished.span), Array(verifyData))

        do {
            _ = try TLS13HandshakeCodec.parseFinished(finished.span, hashByteCount: 48)
            XCTFail("finished message with the wrong hash length was accepted")
        } catch {
            XCTAssertEqual(error, .invalidFinished)
        }
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
