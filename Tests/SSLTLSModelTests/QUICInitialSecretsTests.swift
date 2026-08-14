import SSLCore
import SSLQUIC
import XCTest

final class QUICInitialSecretsTests: XCTestCase {
    func testRFC9001InitialSecretsVector() throws {
        let connectionID = bytes("8394c8f03e515708")
        let secrets = try QUICInitialSecrets(destinationConnectionID: connectionID.span)
        XCTAssertEqual(
            secrets.withClientInitialSecret { copy($0) },
            bytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        )
        XCTAssertEqual(
            secrets.withServerInitialSecret { copy($0) },
            bytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        )
        XCTAssertEqual(
            secrets.withClientKey { copy($0) },
            bytes("1f369613dd76d5467730efcbe3b1a22d")
        )
        XCTAssertEqual(
            secrets.withClientIV { copy($0) },
            bytes("fa044b2f42a3fd3b46fb255c")
        )
        XCTAssertEqual(
            secrets.withClientHeaderProtectionKey { copy($0) },
            bytes("9f50449e04a0e810283a1e9933adedd2")
        )
    }

    func testDestinationConnectionIDLimitIsTyped() {
        let connectionID = ContiguousArray<UInt8>(repeating: 0, count: 21)
        do {
            _ = try QUICInitialSecrets(destinationConnectionID: connectionID.span)
            XCTFail("an oversized destination connection ID was accepted")
        } catch {
            XCTAssertEqual(
                error,
                .invalidDestinationConnectionIDLength(actual: 21)
            )
        }
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
}
