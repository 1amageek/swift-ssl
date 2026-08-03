import SSLCore
import SSLCrypto
import SSLTLS
import SSLX509
import XCTest

final class TLS13SigningKeyTests: XCTestCase {
  func testImportsEd25519PKCS8() throws {
    let seed = bytes(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var inner = ContiguousArray<UInt8>([0x04, 0x20])
    inner.append(contentsOf: seed)
    let privateKeyInfo = try PrivateKeyInfo(
      der: makePrivateKeyInfo(
        algorithmIdentifier: [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70],
        privateKey: inner
      ).span
    )
    let signingKey = try TLS13SigningKey(privateKeyInfo: consume privateKeyInfo)
    XCTAssertEqual(signingKey.signatureScheme, .ed25519)
    _ = consume signingKey
  }

  func testImportsP256PKCS8WithoutInnerCurve() throws {
    var scalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    scalar[31] = 1
    let privateKeyInfo = try PrivateKeyInfo(
      der: makeP256PrivateKeyInfo(scalar: scalar, publicKey: nil).span
    )
    let signingKey = try TLS13SigningKey(privateKeyInfo: consume privateKeyInfo)
    XCTAssertEqual(signingKey.signatureScheme, .ecdsaP256SHA256)
    _ = consume signingKey
  }

  func testRejectsMismatchedP256PublicKeyInPKCS8() throws {
    var scalar = ContiguousArray<UInt8>(repeating: 0, count: 32)
    scalar[31] = 1
    var mismatchedPublicKey = ContiguousArray<UInt8>(repeating: 0, count: 65)
    mismatchedPublicKey[0] = 0x04
    let privateKeyInfo = try PrivateKeyInfo(
      der: makeP256PrivateKeyInfo(
        scalar: scalar,
        publicKey: mismatchedPublicKey
      ).span
    )

    do {
      let key = try TLS13SigningKey(privateKeyInfo: consume privateKeyInfo)
      _ = consume key
      XCTFail("a mismatched embedded P-256 public key was accepted")
    } catch {
      XCTAssertEqual(error, .publicKeyMismatch)
    }
  }

  func testImportsRSAPKCS8() throws {
    let privateKeyInfo = try PrivateKeyInfo(
      der: makePrivateKeyInfo(
        algorithmIdentifier: [
          0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
          0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        ],
        privateKey: rsaPKCS1PrivateKey()
      ).span
    )
    let signingKey = try TLS13SigningKey(privateKeyInfo: consume privateKeyInfo)
    XCTAssertEqual(signingKey.signatureScheme, .rsaPSSRSAESHA256)
    _ = consume signingKey
  }

  private func makeP256PrivateKeyInfo(
    scalar: ContiguousArray<UInt8>,
    publicKey: ContiguousArray<UInt8>?
  ) -> ContiguousArray<UInt8> {
    var body = ContiguousArray<UInt8>([0x02, 0x01, 0x01])
    appendTLV(tag: 0x04, content: scalar, to: &body)
    if let publicKey {
      var bitString = ContiguousArray<UInt8>([0])
      bitString.append(contentsOf: publicKey)
      appendTLV(tag: 0x81, content: bitString, to: &body)
    }
    var ecPrivateKey = ContiguousArray<UInt8>()
    appendTLV(tag: 0x30, content: body, to: &ecPrivateKey)
    return makePrivateKeyInfo(
      algorithmIdentifier: [
        0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      ],
      privateKey: ecPrivateKey
    )
  }

  private func makePrivateKeyInfo(
    algorithmIdentifier: ContiguousArray<UInt8>,
    privateKey: ContiguousArray<UInt8>
  ) -> ContiguousArray<UInt8> {
    var body = ContiguousArray<UInt8>([0x02, 0x01, 0x00])
    body.append(contentsOf: algorithmIdentifier)
    appendTLV(tag: 0x04, content: privateKey, to: &body)
    var result = ContiguousArray<UInt8>()
    appendTLV(tag: 0x30, content: body, to: &result)
    return result
  }

  private func appendTLV(
    tag: UInt8,
    content: ContiguousArray<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) {
    output.append(tag)
    appendDERLength(content.count, to: &output)
    output.append(contentsOf: content)
  }

  private func appendDERLength(
    _ length: Int,
    to output: inout ContiguousArray<UInt8>
  ) {
    if length < 128 {
      output.append(UInt8(length))
      return
    }
    var encoded = ContiguousArray<UInt8>()
    var value = length
    while value > 0 {
      encoded.insert(UInt8(truncatingIfNeeded: value), at: 0)
      value >>= 8
    }
    output.append(0x80 | UInt8(encoded.count))
    output.append(contentsOf: encoded)
  }

  private func rsaPKCS1PrivateKey() -> ContiguousArray<UInt8> {
    bytes(
      "308204a30201000282010100daff26f7df96632c4d130150fc81d99f6d1913e98dd62dbe34d772e926602c94e30c6839d6d60534b9e13c4ae0717aff5bea4978bc07f9372e1cf1fe59e44af195888d435b511564b3dbdebabf2b0ee7b8f9ef02c5379c7ca237ca32b32c6edc1469e8a2943e079225f36820d96655817f14c27d0eb36007f6f7ccfc2c58adec61d57cdb1481aca798529cd0bbae9dac029c43cf5c1e83236585670373aa9852f226adc2697b266137b965d9954072938d3bb6d6c009dc228737b9cd1988e4183582714973f2ba34a7159f24829000dbb6167c3edfd2899e73b7d20b6c3ef347e072fe2cfd458282ffc12ea537a7264f88b63480c3d5218d9ae9118ed2f4a36102030100010282010030a2f82996cb948cf3352456b32db78253bd7d11a2c18d792fcd25a52833b5d2ff35f333dd45bcf43fd0090eec17e7e42caab4d48e960ac0398a8e281a18bc9838c891ef02a9d8617c1c79b3e9df0b396578849f8de352eacf302ac4e5cc1976e145c037d34a8f6de2e5d31b708cecb28ce1b46c07c6c8ae1c285eab26c22f25e61fb39a663feae56fc905311ae0597dd985ceafa8e46cf811900b8b8a61547bc4fa799098dcf9fa34dc3e71262496becf4438a3e3444f5eca8ee5102fe3ec3c6839919f02b65b68a0c4140939cfd7d212f2a7a081cb93dc388c50d9f117240f2c78e7e197bb31f09ea8d2d831929a954fc1f2d909e2ffca4948fe7565a3521d02818100fad1f815d86973e26ada798eb87d705b2c52f03e54168d5c303285581f96d44ca54b17bc8fc3cf52288aead4cbf427abc5a6da828653a453485351060917d0f54604c080009b13efc6d337da25eb7e0740608b9545f03c2d59603b5028c44a202841077ff7b9bd8e9fad4cb54127778ddd42d563b361305656eb891835923ef302818100df84f07679e99799d862c92665bb73747d1574535b271394f7600daa4f429faf63355913dc65a97e221dcd265eb77185cb4ac79b9e5df72b919942adf7604f8c09392b2cbfc67d64cbc624fe85ebe8b8a8123bf4b24717265842fc55e27eb416f2c7eaa2f7c7275d8231048d1740850e477028e7f8299e7e0a4b985b3ed5715b0281807fd2b7c2b24a739364ef3859c2adb2afd433e4596f531af16b62a3d018312eba6cd68b1f3e8904c4130350cfe7ace2f6c840d345079de2b5cabb23249747bae6f4ab014b7a838db279ba34d188d7ad9f96705d5252952ea5d1d19808aeedf1f4d76ee49a93ade5eba476960c1d4b36c3668a63e36e8c4e2d021901020473267f0281800c26e317dddae84611f094f50474e37b02cde6cc1d598b83fecaf7133a49e9fa940f336f93fce6f11793bd3287d5bb5345d123f6feee26e0f4827b908fb169c1b842a6694167de2b5bb4c3101f61cafe370cfebb77f1cb7d6731051cfa3a5f3a1c2ae843c1eacee6138cecad6b0533f6a9c59c43b84732f9b13f98e1e5119f9f02818100afd7c707efd155d648049f9b2d8cf476f318fb7ec57f9e7c1c742974ca5344d867e7744c42e3b5a735602ee55bf28521e3522c30118ed53c94e633b4f0b3dcf5009029ebff61e23b9a03de817374f4491d8d82ecbcf6ef70fd056b9c5b94d9ebd455d1ea1d72df66d404379d63e541fe0765b33c8e32415133ab1079ecce4399"
    )
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        preconditionFailure("fixture contains non-hexadecimal data")
      }
      result.append(byte)
      index = next
    }
    return result
  }
}
