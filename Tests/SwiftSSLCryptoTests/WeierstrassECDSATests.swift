import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class WeierstrassECDSATests: XCTestCase {
    func testP384RFC6979SigningRoundTrips() throws {
        let scalar = bytes(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8" +
            "96D5724E4C70A825F872C9EA60D2EDF5"
        )
        let privateKey = try P384PrivateKey(bytes: scalar.span)
        let expectedPublicKey = bytes(
            "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64" +
            "DEF8F0EA9055866064A254515480BC13" +
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1" +
            "288B231C3AE0D4FE7344FD2533264720"
        )
        let digest = bytes(
            "9A9083505BC92276AEC4BE312696EF7BF3BF603F4BBD381196A029F340585312" +
            "313BCA4A9B5B890EFEE42C77B1EE25FE"
        )
        let expectedSignature = bytes(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C" +
            "81A648152E44ACF96E36DD1E80FABE46" +
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F" +
            "A329C145786E679E7B82C71A38628AC8"
        )
        let signature = try P384ECDSA.sign(
            messageHash: digest.span,
            privateKey: privateKey
        )
        XCTAssertEqual(signature.count, P384ECDSA.signatureByteCount)
        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(copyBytes(privateKey.publicKey().span), Array(expectedPublicKey))
        XCTAssertTrue(try P384ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: privateKey.publicKey().span
        ))
        XCTAssertEqual(
            signature,
            try P384ECDSA.sign(messageHash: digest.span, privateKey: privateKey)
        )
    }

    func testP521RFC6979SigningRoundTrips() throws {
        var scalar = ContiguousArray<UInt8>(repeating: 0, count: 66)
        scalar[65] = 1
        let privateKey = try P521PrivateKey(bytes: scalar.span)
        let digest = bytes(
            "39A5E04AAFF7455D9850C605364F514C11324CE64016960D23D5DC57D3FFD8F4" +
            "9A739468AB8049BF18EEF820CDB1AD6C9015F838556BC7FAD4138B23FDF986C7"
        )
        let signature = try P521ECDSA.sign(
            messageHash: digest.span,
            privateKey: privateKey
        )
        XCTAssertEqual(signature.count, P521ECDSA.signatureByteCount)
        XCTAssertTrue(try P521ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: privateKey.publicKey().span
        ))
        XCTAssertEqual(
            signature,
            try P521ECDSA.sign(messageHash: digest.span, privateKey: privateKey)
        )
    }

    func testP384VerificationAndMutation() throws {
        let publicKey = bytes(
            "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7" +
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
        )
        let digest = bytes(
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED" +
            "8086072BA1E7CC2358BAECA134C825A7"
        )
        let signature = bytes(
            "657A108BD5709DAD00F6FDD003137020A72F916199CE3F488A0C1154EC9F9896D716232B4980EE345D13F17635BB1C900" +
            "3AEB5FD9BE3D8F0BFFA1331F490F2F82CD4335CABD5ABD764D7EC991477E59AE6EDA6475AD5E9C58732E06EB7CA6871"
        )
        XCTAssertTrue(try P384ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: publicKey.span
        ))
        var mutated = signature
        mutated[0] ^= 1
        XCTAssertFalse(try P384ECDSA.verify(
            signature: mutated.span,
            messageHash: digest.span,
            publicKey: publicKey.span
        ))
    }

    func testP521VerificationAndMutation() throws {
        let publicKey = bytes(
            "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66" +
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
        )
        let digest = bytes(
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A" +
            "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
        )
        let signature = bytes(
            "00EF935737F1391BDC574E11C9D1769D3454E8A1611299843931BA10D213CF24FEE3EC80C6B3AF5C1E9A173775BB57CC52F5AD659A2D670D40E113D7E95E5C97D781" +
            "00C3DA0810F3AF0A3D2DF980C22F7F46E451F4DDCE7557871ACCC9BEEB36A10C26BAF3DBE393ACFCEDDA5EDAAB9812DA9F2E05B6A174A4FDBD2FED52ECFFE1503BEF"
        )
        XCTAssertTrue(try P521ECDSA.verify(
            signature: signature.span,
            messageHash: digest.span,
            publicKey: publicKey.span
        ))
        var mutated = signature
        mutated[signature.count - 1] ^= 1
        XCTAssertFalse(try P521ECDSA.verify(
            signature: mutated.span,
            messageHash: digest.span,
            publicKey: publicKey.span
        ))
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
