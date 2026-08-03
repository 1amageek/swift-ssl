import SSLCore
import XCTest

@testable import SSLCrypto

final class RSAPKCS1v15Tests: XCTestCase {
  func testVerifiesIndependentOpenSSLFixturesForEverySupportedHash() throws {
    let key = try RSAPublicKey(
      modulus: modulus.span,
      exponent: 65_537
    )
    let fixtures: [(RSAPKCS1v15Hash, ContiguousArray<UInt8>, ContiguousArray<UInt8>)] = [
      (
        .sha256,
        bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        bytes(
          "5a99a2de514f685be33137296cbbd9ab30a0d56d46f98e89441333c69f0604b1" +
            "3658f0aa2f99e101897f8be4e9a9b41150cceac7fe12cf1a8ae74f6c5d5ad322" +
            "164d9aa0b5f3f98f345782b253f02015166e0a290c99670d1fe5bdef2df0e646" +
            "43d4158da48b3e504d1d309261cb9a3f70f5c4a357c553bfba658596859a37658" +
            "7ab73802e1c910ec0a7b7b6597b2087227304bd417ecb44e85dcb03a53e89cc8" +
            "baaadc88bd302274ba92877457856c3b16147a63d3eda6a2627433088aaf1e22" +
            "c3ae6bf9cad7761aa7376ebc1ebc5e4f22132d0b6490626cc3e6997951b6c4e" +
            "d301c47d6320147518b9f1b361ffb94a8204e80e9a9d98ace21bb01834754a82"
        )
      ),
      (
        .sha384,
        bytes(
          "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da" +
            "274edebfe76f65fbd51ad2f14898b95b"
        ),
        bytes(
          "52c94bcdbfe3afbac8feb61deb43652446c4d37d80e2c36a3a6dbab161eeb916" +
            "ee9a84e96acac71811fc363b4f8a4ad3908b27a0c9cb7556db884dd6bf9dc07a" +
            "f38208f5f05bbf8d8fd9d1ca4a54127ce042d7a71d314d00cb206a65a9cefff" +
            "1e639418fa6cba03b817bd6f25d1341e6904cf98adfc2141125f04cc1eceaa27" +
            "2f5c17f682ff54e911bba7ed46a6e0d7d775f315d116d85f6bae29e373b9088" +
            "ca4b86de992fe651a4bc9e737078212bd5e230b4c27fbe7983cb364f343baabaa" +
            "fe668b34676ccc1141ef24224e3604cab85f773e45f2528b6496f17a91fd79bf" +
            "127e0188eda65bbfef46c1a271430881afb2cc347f6b1005dfbe1895111326b03"
        )
      ),
      (
        .sha512,
        bytes(
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
        bytes(
          "af1e4d902357b71720a6cf4a0138911168a98690167b9b6d9400d9cb376d8b74" +
            "e0e0fb577e8b880a23b5c1046fb2accfc2d4a19d22bc043863325de38ad8f384" +
            "0a1fb6ec06bdf8eed9824c5570411824bbe26943235418069f86a97f6faaed492" +
            "69c8f853da3cd6d34d2dfa93d84f130121e6c8b9d05f3e844ef547aafac47c6" +
            "0a8a82e2b7b5e86049ac87fe85cbd8bee83a127a2bf59a285e2b6f2a9725084" +
            "b37c7b4c8e514b0ac005e5c50ee842965d20eddeb02d477276ec3abfcd94f0f0" +
            "330f546b54f46ffcc3457b8256318ead3a39c4c609f6a5cecb128ca22a40a397" +
            "05ad9edbce27e89ceb3a9df89e3713e0212b060c2556f37ef49e8512fa1e9d4d5"
        )
      ),
    ]

    for (hash, digest, signature) in fixtures {
      XCTAssertTrue(
        try RSAPKCS1v15.verify(
          signature: signature.span,
          messageHash: digest.span,
          publicKey: key,
          hash: hash
        )
      )

      var mutatedSignature = signature
      mutatedSignature[mutatedSignature.count - 1] ^= 1
      XCTAssertFalse(
        try RSAPKCS1v15.verify(
          signature: mutatedSignature.span,
          messageHash: digest.span,
          publicKey: key,
          hash: hash
        )
      )
    }

    let missingNullSignature = bytes(
      "6bea09ef86e28c4a778e7d3e952c0e76913f1953cf98a65a041e2a0cb640f2ab" +
        "c65d75d32e44aab621c3b0dca3793ccd615737036adb14ce2c2528175975a4470" +
        "0dba4b9cb220ec251dc5e9078138fb49f3b75de708892fedc060eb4cd0aac60a" +
        "7c004e400f746afa91d58e38824f6d21030970e09dcee37c39dbd59020012d6d" +
        "57a5cdbff74fb3cc192d01a373764a7ebe50fbf94d208130da5d95826d7f0f50" +
        "094acddd0a9d15f5a0ff60c2d9608f0784466f6e82a11833559ea46978806d94" +
        "174c15e8fe78763edd2e3a53c059efae4f8f96471222d35949a779cd8d91ca47" +
        "dbcfd8dae1d92003a5cd2af8c3ff2d328da4ef31611b0b1c94a1f3a0c6d3404"
    )
    let sha256Digest = fixtures[0].1
    XCTAssertFalse(
      try RSAPKCS1v15.verify(
        signature: missingNullSignature.span,
        messageHash: sha256Digest.span,
        publicKey: key,
        hash: .sha256
      )
    )
  }

  func testRejectsInvalidLengthsAndNonCanonicalSignature() throws {
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)
    let digest = bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    var shortSignature = modulus
    shortSignature.removeLast()
    XCTAssertThrowsError(
      try RSAPKCS1v15.verify(
        signature: shortSignature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256
      )
    ) { error in
      XCTAssertEqual(error as? CryptoInputError, .invalidLength(expected: 256, actual: 255))
    }

    var shortDigest = digest
    shortDigest.removeLast()
    XCTAssertThrowsError(
      try RSAPKCS1v15.verify(
        signature: modulus.span,
        messageHash: shortDigest.span,
        publicKey: key,
        hash: .sha256
      )
    ) { error in
      XCTAssertEqual(error as? CryptoInputError, .invalidLength(expected: 32, actual: 31))
    }

    XCTAssertThrowsError(
      try RSAPKCS1v15.verify(
        signature: modulus.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256
      )
    ) { error in
      XCTAssertEqual(error as? CryptoInputError, .nonCanonicalEncoding)
    }
  }

  private var modulus: ContiguousArray<UInt8> {
    bytes(
      "f4f562eef1868a943e858db385112d5bf64e8e3ee9d671f1a6a2a5a131840ef1" +
        "38eb10e35c2d7dd76ae7f8b18c3881386265a03900d1e438d4747d3044447172" +
        "cad6bc3c85d2f41ad63baf84005857eb14658fbb93a4b3c9f633299e4ddeeeed" +
        "715c7a2b20b8c6ff97c5830aaf5361e1fdb97d219f32033264388d641344ffd2" +
        "28cea97da95c2cc8fd436532acab1bdeab76ddff5dd68d9cc473a0c84f3c4792" +
        "70f3299022c8ed8cefb11bd1ebebb8a4f27c959448cd8f0c9d3946e56d1d552" +
        "160bac17db2d7e1a2066a84cbafba5f07f707f24cbe11e536234e1a6bcd32cd1" +
        "04c0688aa508d3782076f9b9febce621a10791c967b07785369fc665460c3b5a9"
    )
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    let normalized = value.filter { !$0.isWhitespace }
    precondition(normalized.count.isMultiple(of: 2))
    var output = ContiguousArray<UInt8>()
    output.reserveCapacity(normalized.count / 2)
    var index = normalized.startIndex
    while index < normalized.endIndex {
      let next = normalized.index(index, offsetBy: 2)
      output.append(UInt8(normalized[index..<next], radix: 16)!)
      index = next
    }
    return output
  }
}
