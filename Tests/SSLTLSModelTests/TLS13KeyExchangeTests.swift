import SSLCore
import SSLCrypto
import XCTest

@testable import SSLTLS

final class TLS13KeyExchangeTests: XCTestCase {
    func testP256RoundTripRejectsMalformedShareAndIsOneShot() throws {
        let clientKey = try P256PrivateKey(bytes: repeated(0x11, count: 32).span)
        let serverKey = try P256PrivateKey(bytes: repeated(0x22, count: 32).span)
        var client = TLS13P256ClientKeyExchange(privateKey: clientKey)
        var server = TLS13P256ServerKeyExchange(privateKey: serverKey)

        let clientShare = ownedClientShare(client)
        XCTAssertEqual(client.namedGroup, .secp256r1)
        XCTAssertEqual(clientShare.count, 65)
        XCTAssertEqual(clientShare.span[0], 0x04)

        let serverResult = try server.accept(
            clientShare: clientShare.span,
            using: FailingEntropy()
        )
        XCTAssertEqual(serverResult.serverShare.count, 65)
        XCTAssertEqual(serverResult.serverShare.span[0], 0x04)
        let clientSecret = try client.complete(
            serverShare: serverResult.serverShare.span
        )
        XCTAssertEqual(copy(clientSecret), copy(serverResult.sharedSecret))

        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try client.complete(
                serverShare: serverResult.serverShare.span
            )
            _ = consume unused
        }
        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try server.accept(
                clientShare: clientShare.span,
                using: FailingEntropy()
            )
            _ = consume unused
        }

        var malformedServer = TLS13P256ServerKeyExchange(
            privateKey: try P256PrivateKey(bytes: repeated(0x33, count: 32).span)
        )
        var malformedShare = copy(clientShare.span)
        malformedShare[0] = 0x02
        do {
            let unused = try malformedServer.accept(
                clientShare: malformedShare.span,
                using: FailingEntropy()
            )
            _ = consume unused
            XCTFail("compressed P-256 share was accepted")
        } catch {
            XCTAssertEqual(error, .crypto(.invalidPeerKey))
        }
    }

    func testX25519RoundTripAndOneShotState() throws {
        let clientKey = try X25519PrivateKey(bytes: repeated(0x11, count: 32).span)
        let serverKey = try X25519PrivateKey(bytes: repeated(0x22, count: 32).span)
        var client = TLS13X25519ClientKeyExchange(privateKey: clientKey)
        var server = TLS13X25519ServerKeyExchange(privateKey: serverKey)

        let clientShare = ownedClientShare(client)
        XCTAssertEqual(client.namedGroup, .x25519)
        XCTAssertEqual(clientShare.count, TLS13NamedGroup.x25519.clientShareByteCount)

        let serverResult = try server.accept(clientShare: clientShare.span, using: FailingEntropy())
        XCTAssertEqual(
            serverResult.serverShare.count,
            TLS13NamedGroup.x25519.serverShareByteCount
        )
        let clientSecret = try client.complete(serverShare: serverResult.serverShare.span)
        XCTAssertEqual(copy(clientSecret), copy(serverResult.sharedSecret))

        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try client.complete(serverShare: serverResult.serverShare.span)
            _ = consume unused
        }
        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try server.accept(clientShare: clientShare.span, using: FailingEntropy())
            _ = consume unused
        }
    }

    func testHybridRoundTripUsesDraftWireOrdering() throws {
        var client = try makeHybridClient()
        var server = try makeHybridServer()

        let clientShare = ownedClientShare(client)
        XCTAssertEqual(client.namedGroup, .x25519MLKEM768)
        XCTAssertEqual(clientShare.count, 1_216)
        XCTAssertEqual(
            copy(clientShare.span.extracting(0..<MLKEM768.PublicKey.byteCount)).count,
            MLKEM768.PublicKey.byteCount
        )
        XCTAssertEqual(
            copy(clientShare.span.extracting(MLKEM768.PublicKey.byteCount..<clientShare.count))
                .count,
            X25519PublicKey.byteCount
        )

        let serverResult = try server.accept(
            clientShare: clientShare.span,
            using: FixedEntropy(bytes: sequential(count: 32, seed: 0x80))
        )
        XCTAssertEqual(serverResult.serverShare.count, 1_120)
        XCTAssertEqual(
            copy(
                serverResult.serverShare.span.extracting(0..<MLKEM768.Encapsulation.byteCount)
            ).count,
            MLKEM768.Encapsulation.byteCount
        )
        XCTAssertEqual(
            copy(
                serverResult.serverShare.span.extracting(
                    MLKEM768.Encapsulation.byteCount..<serverResult.serverShare.count
                )
            ).count,
            X25519PublicKey.byteCount
        )

        let clientSecret = try client.complete(serverShare: serverResult.serverShare.span)
        XCTAssertEqual(clientSecret.count, 64)
        XCTAssertEqual(copy(clientSecret), copy(serverResult.sharedSecret))

        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try client.complete(serverShare: serverResult.serverShare.span)
            _ = consume unused
        }
        assertInvalidState { () throws(TLS13KeyExchangeError) in
            let unused = try server.accept(
                clientShare: clientShare.span,
                using: FixedEntropy(bytes: repeated(0x44, count: 32))
            )
            _ = consume unused
        }
    }

    func testHybridServerRejectsMalformedClientShares() throws {
        let sourceClient = try makeHybridClient()
        let validShare = ownedClientShare(sourceClient)

        do {
            var server = try makeHybridServer()
            let shortShare = validShare.span.extracting(0..<(validShare.count - 1))
            let unused = try server.accept(
                clientShare: shortShare,
                using: FixedEntropy(bytes: repeated(0x33, count: 32))
            )
            _ = consume unused
            XCTFail("short hybrid client share was accepted")
        } catch {
            XCTAssertEqual(error, .invalidShareLength(expected: 1_216, actual: 1_215))
        }

        do {
            var malformed = copy(validShare.span)
            malformed[0] = 0xFF
            malformed[1] = (malformed[1] & 0xF0) | 0x0F
            var server = try makeHybridServer()
            let unused = try server.accept(
                clientShare: malformed.span,
                using: FixedEntropy(bytes: repeated(0x33, count: 32))
            )
            _ = consume unused
            XCTFail("non-canonical ML-KEM public key was accepted")
        } catch {
            XCTAssertEqual(error, .kem(.invalidPublicKeyEncoding))
        }

        do {
            var zeroX25519 = copy(validShare.span)
            var index = MLKEM768.PublicKey.byteCount
            while index < zeroX25519.count {
                zeroX25519[index] = 0
                index += 1
            }
            var server = try makeHybridServer()
            let unused = try server.accept(
                clientShare: zeroX25519.span,
                using: FixedEntropy(bytes: repeated(0x33, count: 32))
            )
            _ = consume unused
            XCTFail("all-zero X25519 client share was accepted")
        } catch {
            XCTAssertEqual(error, .crypto(.invalidPeerKey))
        }
    }

    func testHybridClientRejectsMalformedServerShareAndUsesImplicitKEMRejection() throws {
        do {
            var client = try makeHybridClient()
            let shortShare = repeated(0, count: 1_119)
            let unused = try client.complete(serverShare: shortShare.span)
            _ = consume unused
            XCTFail("short hybrid server share was accepted")
        } catch {
            XCTAssertEqual(error, .invalidShareLength(expected: 1_120, actual: 1_119))
        }

        do {
            var client = try makeHybridClient()
            var server = try makeHybridServer()
            let clientShare = ownedClientShare(client)
            let serverResult = try server.accept(
                clientShare: clientShare.span,
                using: FixedEntropy(bytes: sequential(count: 32, seed: 0x60))
            )
            var zeroX25519 = copy(serverResult.serverShare.span)
            var index = MLKEM768.Encapsulation.byteCount
            while index < zeroX25519.count {
                zeroX25519[index] = 0
                index += 1
            }
            let unused = try client.complete(serverShare: zeroX25519.span)
            _ = consume unused
            XCTFail("all-zero X25519 server share was accepted")
        } catch {
            XCTAssertEqual(error, .crypto(.invalidPeerKey))
        }

        var client = try makeHybridClient()
        var server = try makeHybridServer()
        let clientShare = ownedClientShare(client)
        let serverResult = try server.accept(
            clientShare: clientShare.span,
            using: FixedEntropy(bytes: sequential(count: 32, seed: 0x40))
        )
        var tamperedServerShare = copy(serverResult.serverShare.span)
        tamperedServerShare[0] ^= 0x01
        let rejectedSecret = try client.complete(serverShare: tamperedServerShare.span)
        XCTAssertNotEqual(copy(rejectedSecret), copy(serverResult.sharedSecret))
    }

    func testHybridServerPropagatesEntropyFailure() throws {
        let client = try makeHybridClient()
        var server = try makeHybridServer()
        let clientShare = ownedClientShare(client)

        do {
            let unused = try server.accept(clientShare: clientShare.span, using: FailingEntropy())
            _ = consume unused
            XCTFail("hybrid encapsulation ignored entropy failure")
        } catch {
            XCTAssertEqual(error, .kem(.entropy(.sourceRejected)))
        }
    }

    private func makeHybridClient()
        throws(TLS13KeyExchangeError) -> TLS13X25519MLKEM768ClientKeyExchange
    {
        try TLS13X25519MLKEM768ClientKeyExchange.generate(
            mlkemEntropy: FixedEntropy(bytes: sequential(count: 64, seed: 0x10)),
            x25519Entropy: FixedEntropy(bytes: sequential(count: 32, seed: 0x30))
        )
    }

    private func makeHybridServer()
        throws(TLS13KeyExchangeError) -> TLS13X25519MLKEM768ServerKeyExchange
    {
        try TLS13X25519MLKEM768ServerKeyExchange.generate(
            using: FixedEntropy(bytes: sequential(count: 32, seed: 0x50))
        )
    }

    private func assertInvalidState(
        _ body: () throws(TLS13KeyExchangeError) -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        do {
            try body()
            XCTFail("one-shot key exchange accepted a second operation", file: file, line: line)
        } catch {
            XCTAssertEqual(error, .invalidState, file: file, line: line)
        }
    }

    private func copy(_ secret: borrowing SecretBytes) -> ContiguousArray<UInt8> {
        secret.withBorrowedBytes { copy($0) }
    }

    private func ownedClientShare<Client: TLS13ClientKeyExchange & ~Copyable>(
        _ client: borrowing Client
    ) -> OwnedBytes {
        client.withClientShare { OwnedBytes(copying: $0) }
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

    private func repeated(_ byte: UInt8, count: Int) -> ContiguousArray<UInt8> {
        ContiguousArray(repeating: byte, count: count)
    }

    private func sequential(count: Int, seed: UInt8) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(count)
        var index = 0
        while index < count {
            result.append(seed &+ UInt8(truncatingIfNeeded: index))
            index += 1
        }
        return result
    }

    private struct FixedEntropy: EntropySource {
        let bytes: ContiguousArray<UInt8>

        func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
            guard destination.count == bytes.count else {
                throw .partialFill(expected: destination.count, actual: bytes.count)
            }
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }

    private struct FailingEntropy: EntropySource {
        func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
            if !destination.isEmpty {
                destination[0] = 0xA5
            }
            throw .sourceRejected
        }
    }
}
