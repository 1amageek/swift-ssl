import SwiftSSLCore
import SwiftSSLCrypto
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

    func testDeterministicClientServerHandshakeCompletes() throws {
        let seed = deterministicSeed()
        let serverPublicKey = deterministicServerPublicKey()
        let certificate = deterministicCertificate()
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let clientEphemeral = try X25519PrivateKey(bytes: ContiguousArray(repeating: 0x11, count: 32).span)
        let serverEphemeral = try X25519PrivateKey(bytes: ContiguousArray(repeating: 0x22, count: 32).span)
        let signingKey = try Ed25519PrivateKey(seed: seed.span)
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: serverPublicKey.span,
            verificationInstant: verificationInstant
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: certificate.span,
            signingKey: signingKey,
            verificationInstant: verificationInstant
        )

        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        let clientFinished = try client.receive(serverFlight.bytes.span)
        let serverFinished = try server.receive(clientFinished.bytes.span)

        XCTAssertTrue(client.isEstablished)
        XCTAssertTrue(server.isEstablished)
        XCTAssertTrue(clientFinished.actions.contains(.handshakeComplete))
        XCTAssertTrue(serverFinished.actions.contains(.handshakeConfirmed))

        let applicationData = ContiguousArray<UInt8>([0x61, 0x70, 0x70, 0x2D, 0x31])
        let applicationOutput = try client.sendApplicationData(applicationData.span)
        let received = try server.receiveApplicationRecord(applicationOutput.bytes.span)
        XCTAssertEqual(copy(received.span), Array(applicationData))

        let response = ContiguousArray<UInt8>([0x6F, 0x6B])
        let responseOutput = try server.sendApplicationData(response.span)
        let clientReceived = try client.receiveApplicationRecord(responseOutput.bytes.span)
        XCTAssertEqual(copy(clientReceived.span), Array(response))
    }

    func testClientRejectsTamperedServerFlight() throws {
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let serverEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        var server = try TLS13ServerHandshake(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: serverEphemeral,
            certificateDER: deterministicCertificate().span,
            signingKey: signingKey,
            verificationInstant: verificationInstant
        )
        let clientEphemeral = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x11, count: 32).span
        )
        var client = try TLS13ClientHandshake(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: clientEphemeral,
            expectedServerPublicKey: deterministicServerPublicKey().span,
            verificationInstant: verificationInstant
        )

        let clientHello = try client.start()
        let serverFlight = try server.receive(clientHello.bytes.span)
        var tampered = ContiguousArray(copy(serverFlight.bytes.span))
        tampered[tampered.count - 1] ^= 0x01

        do {
            _ = try client.receive(tampered.span)
            XCTFail("tampered server flight was accepted")
        } catch let error {
            XCTAssertEqual(error, .record(.authenticationFailed))
        }
    }

    func testServerRejectsCertificateOutsideVerificationWindow() throws {
        let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
        let ephemeralKey = try X25519PrivateKey(
            bytes: ContiguousArray(repeating: 0x22, count: 32).span
        )
        let verificationInstant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_800_000_000,
            nanoseconds: 0
        )

        do {
            _ = try TLS13ServerHandshake(
                random: ContiguousArray(repeating: 0x02, count: 32).span,
                ephemeralKey: ephemeralKey,
                certificateDER: deterministicCertificate().span,
                signingKey: signingKey,
                verificationInstant: verificationInstant
            )
            XCTFail("certificate outside the verification window was accepted")
        } catch let error {
            XCTAssertEqual(error, .certificateNotValid)
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

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            result.append(UInt8(value[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    private func deterministicSeed() -> ContiguousArray<UInt8> {
        bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    }

    private func deterministicServerPublicKey() -> ContiguousArray<UInt8> {
        bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    }

    private func deterministicCertificate() -> ContiguousArray<UInt8> {
        bytes(
            "3081a6305a020101300506032b65703000301e170d3234303130313030303030305a" +
            "170d3235303130313030303030305a3000302a300506032b6570032100" +
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" +
            "300506032b6570034100" +
            "37dfbf24eb692e0be9243a10e90e7a420528f6dcd6032898dca956d51ce3a286b" +
            "15596380832a60cc57d2a84f843c774ffe0a7b462a9556f76751a870d5c7901"
        )
    }
}
