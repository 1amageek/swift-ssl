import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class WeierstrassECDHTests: XCTestCase {
    func testP384OpenSSLSharedSecretVectorAndPeerMutation() throws {
        let privateKey = try P384PrivateKey(bytes: bytes(
            "C88CD892A2C9A7262A7B7B34B06B6EDB46AD143EE1DAD4C54721DB8F621BF15D" +
            "513598DA63C5FDE8BCE5DC8A7A849E91"
        ).span)
        let peer = try P384PublicKey(bytes: bytes(
            "04DB05BD8261A06555DC420BF70E8BCF32894B021AFF4F20C4A6276B515257" +
            "1F6B17C90D38F1707543D36939970D1172F0C582A60030829CE1027257AE4F" +
            "62D993D5E3D48ADC8EFF795E391A D24033C4CBC8A7D8AFC9CF764474841706" +
            "DAA9A47A"
        ).span)
        let expected = bytes(
            "223F051FC026F2A8A4FBED85E34C57B219A04EA1C2F347BF17F263240C51" +
            "375A892579A1E91FC1DA155B98185F1223F3"
        )
        let shared = try P384.sharedSecret(privateKey: privateKey, peerPublicKey: peer)
        shared.withBorrowedBytes { actual in
            XCTAssertEqual(copyBytes(actual), Array(expected))
        }

        var mutated = ContiguousArray(copyBytes(peer.span))
        mutated[mutated.count - 1] ^= 1
        XCTAssertThrowsError(try P384PublicKey(bytes: mutated.span))
    }

    func testP521OpenSSLSharedSecretVectorAndPeerMutation() throws {
        let privateKey = try P521PrivateKey(bytes: bytes(
            "0108293610B19B47BE8433B66DCAEB59F0D2507442C30A98A89CECF667D40C" +
            "6880920E433BAA1FA3E95E3E22FAA4A6B0BB40AD41007E62A9DE64B0592ED1" +
            "EE241456"
        ).span)
        let peer = try P521PublicKey(bytes: bytes(
            "0401401DCC127B70019128BD9E5B096EF1E732144B255648FD868F4AA84D" +
            "923564D4226057D89773CC779F9D9AE3A64A1F60C07FB4FC1C4065F735377" +
            "6F796228BCA540143439EE7195DC225B67C59F551DA8176F6EC05D08D896C" +
            "CF0C04D320BB25550A9ACE5CC1B4D12C2E5D225E08085B8FA42CD55E3D6D" +
            "2D1D76F3F99B38C466911A8E"
        ).span)
        let expected = bytes(
            "0179C713A586FB44F07AAC3122245A23B56B021198E4A80ED73CD34C5B4D" +
            "7A9E3A47333D7967F CDBCF5ABE8433629381DFCE70E0EFF6920D99AE1D0A" +
            "95625FA947AE"
        )
        let shared = try P521.sharedSecret(privateKey: privateKey, peerPublicKey: peer)
        shared.withBorrowedBytes { actual in
            XCTAssertEqual(copyBytes(actual), Array(expected))
        }

        var mutated = ContiguousArray(copyBytes(peer.span))
        mutated[mutated.count - 1] ^= 1
        XCTAssertThrowsError(try P521PublicKey(bytes: mutated.span))
    }

    func testGeneratedP521KeyMasksUnusedLeadingBits() throws {
        let entropy = FixedEntropy(bytes: ContiguousArray([UInt8(0xFF)] + Array(repeating: 0, count: 65)))
        let key = try P521PrivateKey.generate(using: entropy)
        XCTAssertEqual(key.publicKey().span.count, P521PublicKey.uncompressedByteCount)
    }

    private func bytes(_ value: String) -> ContiguousArray<UInt8> {
        let compact = value.filter { !$0.isWhitespace }
        var result = ContiguousArray<UInt8>()
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            result.append(UInt8(compact[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    private func copyBytes(_ value: Span<UInt8>) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(value.count)
        var index = 0
        while index < value.count {
            result.append(value[index])
            index += 1
        }
        return result
    }
}

private struct FixedEntropy: EntropySource {
    let bytes: ContiguousArray<UInt8>

    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError) {
        guard destination.count == bytes.count else {
            throw .partialFill(expected: destination.count, actual: bytes.count)
        }
        var index = 0
        while index < destination.count {
            destination[index] = bytes[index]
            index += 1
        }
    }
}
