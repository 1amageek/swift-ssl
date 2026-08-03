import SSLCore
import SSLCrypto

@main
enum NISTVerificationValidationCommand {
  enum Failure: Error {
    case invalidHexadecimal
    case verification
  }

  static func main() throws {
    #if SWIFT_SSL_NIST_P256
    try validateP256()
    #elseif SWIFT_SSL_NIST_P384_VALID
    try validateP384(mutated: false)
    #elseif SWIFT_SSL_NIST_P384_MUTATED
    try validateP384(mutated: true)
    #elseif SWIFT_SSL_NIST_P521_VALID
    try validateP521(mutated: false)
    #elseif SWIFT_SSL_NIST_P521_MUTATED
    try validateP521(mutated: true)
    #else
    try validateP256()
    try validateP384(mutated: false)
    try validateP384(mutated: true)
    try validateP521(mutated: false)
    try validateP521(mutated: true)
    #endif
    print("swift-ssl NIST verification validation: ok")
  }

  private static func validateP256() throws {
    let publicKeyBytes = try hexadecimalBytes(
      "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    )
    let digest = try hexadecimalBytes(
      "172B1296FEDDD5E2C0B6300615142D3C4F6D375E5CB70ED8CFA9220CCEB94BE2"
    )
    var signature = try hexadecimalBytes(
      "B186796906E26621D8940DDDF79330F38FB9EB6D8D8D88236E7223C71119C8CE" +
        "FA037545B606E053DBFB53AFF1D182250E1CD6BEF8EF5B6F56C35C0B3EE8AF64"
    )
    let key = try P256PublicKey(bytes: publicKeyBytes.span)
    guard try P256ECDSA.verify(
      signature: signature.span,
      messageHash: digest.span,
      using: key
    ) else {
      throw Failure.verification
    }
    signature[0] ^= 1
    guard try !P256ECDSA.verify(
      signature: signature.span,
      messageHash: digest.span,
      using: key
    ) else {
      throw Failure.verification
    }
  }

  private static func validateP384(mutated: Bool) throws {
    let publicKeyBytes = try hexadecimalBytes(
      "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A" +
        "385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292" +
        "DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C9" +
        "0EA0E5F"
    )
    let digest = try hexadecimalBytes(
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED" +
        "8086072BA1E7CC2358BAECA134C825A7"
    )
    var signature = try hexadecimalBytes(
      "657A108BD5709DAD00F6FDD003137020A72F916199CE3F488A0C1154EC9F989" +
        "6D716232B4980EE345D13F17635BB1C9003AEB5FD9BE3D8F0BFFA1331F490F2" +
        "F82CD4335CABD5ABD764D7EC991477E59AE6EDA6475AD5E9C58732E06EB7CA6" +
        "871"
    )
    let key = try P384PublicKey(bytes: publicKeyBytes.span)
    if mutated {
      signature[0] ^= 1
    }
    let valid = try P384ECDSA.verify(
      signature: signature.span,
      messageHash: digest.span,
      using: key
    )
    guard valid != mutated else {
      throw Failure.verification
    }
  }

  private static func validateP521(mutated: Bool) throws {
    let publicKeyBytes = try hexadecimalBytes(
      "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B" +
        "4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31" +
        "C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817" +
        "AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C2408" +
        "8BE94769FD16650"
    )
    let digest = try hexadecimalBytes(
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A" +
        "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
    )
    var signature = try hexadecimalBytes(
      "00EF935737F1391BDC574E11C9D1769D3454E8A1611299843931BA10D213CF2" +
        "4FEE3EC80C6B3AF5C1E9A173775BB57CC52F5AD659A2D670D40E113D7E95E5" +
        "C97D78100C3DA0810F3AF0A3D2DF980C22F7F46E451F4DDCE7557871ACCC9B" +
        "EEB36A10C26BAF3DBE393ACFCEDDA5EDAAB9812DA9F2E05B6A174A4FDBD2FE" +
        "D52ECFFE1503BEF"
    )
    let key = try P521PublicKey(bytes: publicKeyBytes.span)
    if mutated {
      signature[signature.count - 1] ^= 1
    }
    let valid = try P521ECDSA.verify(
      signature: signature.span,
      messageHash: digest.span,
      using: key
    )
    guard valid != mutated else {
      throw Failure.verification
    }
  }

  private static func hexadecimalBytes(
    _ hexadecimal: String
  ) throws(Failure) -> ContiguousArray<UInt8> {
    let characters = ContiguousArray(hexadecimal.utf8)
    guard characters.count & 1 == 0 else {
      throw .invalidHexadecimal
    }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(characters.count / 2)
    var index = 0
    while index < characters.count {
      guard let high = hexadecimalNibble(characters[index]),
        let low = hexadecimalNibble(characters[index + 1])
      else {
        throw .invalidHexadecimal
      }
      result.append(high << 4 | low)
      index += 2
    }
    return result
  }

  private static func hexadecimalNibble(_ character: UInt8) -> UInt8? {
    switch character {
    case 0x30...0x39: character - 0x30
    case 0x41...0x46: character - 0x41 + 10
    case 0x61...0x66: character - 0x61 + 10
    default: nil
    }
  }
}
