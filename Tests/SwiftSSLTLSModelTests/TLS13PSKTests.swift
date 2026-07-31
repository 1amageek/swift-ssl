import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS
import XCTest

final class TLS13PSKTests: XCTestCase {
    func testPreSharedKeyExtensionRoundTrip() throws {
        let identity = try TLS13PSKIdentity(
            identity: ContiguousArray<UInt8>([0xA0, 0xB0]).span,
            obfuscatedTicketAge: 123
        )
        let binder = try TLS13PSKBinder(
            value: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span
        )
        let extensionValue = try TLS13PreSharedKeyExtension(
            identities: ContiguousArray([identity]),
            binders: ContiguousArray([binder])
        )
        let encoded = try extensionValue.encodedValue()
        let parsed = try TLS13PreSharedKeyExtension.parse(encoded.span)
        XCTAssertEqual(parsed.identities.count, 1)
        XCTAssertEqual(parsed.binders.count, 1)
        let parsedIdentity = parsed.identities[0]
        let parsedBinder = parsed.binders[0]
        XCTAssertEqual(parsedIdentity.obfuscatedTicketAge, 123)
        XCTAssertEqual(copy(parsedIdentity.identity.span), [0xA0, 0xB0])
        XCTAssertEqual(copy(parsedBinder.value.span), Array(repeating: 0x11, count: 32))
    }

    func testClientHelloCarriesPreSharedKeyAsLastExtension() throws {
        let identity = try TLS13PSKIdentity(
            identity: ContiguousArray<UInt8>([1, 2, 3]).span,
            obfuscatedTicketAge: 7
        )
        let binder = try TLS13PSKBinder(
            value: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
        )
        let psk = try TLS13PreSharedKeyExtension(
            identities: ContiguousArray([identity]),
            binders: ContiguousArray([binder])
        )
        let hello = try TLS13HandshakeCodec.makeClientHello(
            random: ContiguousArray(repeating: 0x33, count: 32).span,
            keyShare: ContiguousArray(repeating: 0x44, count: 32).span,
            preSharedKey: psk
        )
        let parsed = try TLS13HandshakeCodec.parseClientHello(hello.span)
        XCTAssertEqual(parsed.preSharedKey, psk)
    }

    func testPreSharedKeyExtensionRejectsDuplicateIdentities() throws {
        let identity = try TLS13PSKIdentity(
            identity: ContiguousArray<UInt8>([0xAA]).span,
            obfuscatedTicketAge: 0
        )
        let firstBinder = try TLS13PSKBinder(
            value: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span
        )
        let secondBinder = try TLS13PSKBinder(
            value: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
        )
        do {
            _ = try TLS13PreSharedKeyExtension(
                identities: ContiguousArray([identity, identity]),
                binders: ContiguousArray([firstBinder, secondBinder])
            )
            XCTFail("duplicate PSK identities were accepted")
        } catch {
            XCTAssertEqual(error, .duplicateIdentity)
        }
    }

    func testBinderVerificationIsConstantTimeAndSuiteSized() throws {
        let psk = try SecretBytes(
            copying: ContiguousArray<UInt8>(repeating: 0x55, count: 32).span
        )
        let transcriptHash = ContiguousArray<UInt8>(repeating: 0x66, count: 32)
        let binder = try TLS13PSKBinder.compute(
            preSharedKey: psk,
            cipherSuite: .aes128GCM_SHA256,
            transcriptHash: transcriptHash.span
        )
        XCTAssertTrue(
            try TLS13PSKBinder.verify(
                preSharedKey: psk,
                cipherSuite: .aes128GCM_SHA256,
                transcriptHash: transcriptHash.span,
                binder: binder.span
            )
        )
        var modified = ContiguousArray(copy(binder.span))
        modified[0] ^= 1
        XCTAssertFalse(
            try TLS13PSKBinder.verify(
                preSharedKey: psk,
                cipherSuite: .aes128GCM_SHA256,
                transcriptHash: transcriptHash.span,
                binder: modified.span
            )
        )
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
