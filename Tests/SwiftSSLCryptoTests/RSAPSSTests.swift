import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class RSAPSSTests: XCTestCase {
  func testSHA256PSSVerificationAndMutation() throws {
    let modulus = bytes(
      "B5E9172F65A2FB7D5D287F277A5CC182581497CF9FFC779839113DAD70B8EA9E35EDB39C95C23ACC949B953132C0CDA4723C3E13E3FFBA97345FA8BA4947460B1E833B4EC5793402CC19AFB3E9B3C406F9F423EE47C504C4E790314BE876EF4B068EF85C021349459A0E1B05B9E860864797AC588AB6F70EC55452915D0C3DDE99A0B4AA566F759A0BDA20080F96254512B4BDBFF4E0AAF68263B9BD513D16EBF797D71BB8AA02611F544DB3C80F1EC5B60BD185D36ADBBDE988EBB9F6EE332E7501F66A1413DD348D4F7F78D9F93172A029BAC6F4072EB81AF4CC9692D6215304DD8C68F10F100925AD50987FC5D7FA1084532E90CED8F02A1BED6D92DE8A65"
    )
    let digest = bytes("29AEB90FADDF4D7ECE03FA92CFFB85213640FC5ED228181BD7BDE889FF3E7A5E")
    let signature = bytes(
      "6FA921CFAC77C99B35BFCD6722264EF9C4B508542AF7A517134938F75726E8E5B696A019E709826339B0AA726B8FE02606D8F2DB94C345C9BC3112D97CAC3DF6E166EDE61468C6D21A61FD573387F6770B3D13E44FD510FA9B9AABA6BB25C94EBED5E023FB4E531029DF7D35BD84AC5D34BAB24A349A537FCC1BAD294A6CD1E17F917582603AF2468308C7E8E940A49B036ECED9791D9C593FA6B570B44ACC8B90EF80BCC69675FDE2BB1E3BDD9EA5F0461A87D5A8F427DB1ABFFE4443CFEFFFBF13532C876975D9270E709E4D504457CBD124A5132DF4CEBF7E1B48A3BAF5E6CBC3D4D7E27387204698250E1E7CD5C6DE8CF800DA203CD73D938FF911C1B5C4"
    )
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)

    var shortSignature = signature
    shortSignature.removeLast()
    do {
      _ = try RSAPSS.verify(
        signature: shortSignature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      )
      XCTFail("a short signature was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 256, actual: 255))
    }

    var shortDigest = digest
    shortDigest.removeLast()
    do {
      _ = try RSAPSS.verify(
        signature: signature.span,
        messageHash: shortDigest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      )
      XCTFail("a short digest was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 32, actual: 31))
    }

    do {
      _ = try RSAPSS.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: -1
      )
      XCTFail("a negative salt length was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 0, actual: -1))
    }

    XCTAssertTrue(
      try RSAPSS.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      ))

    var mutated = signature
    mutated[mutated.count - 1] ^= 1
    XCTAssertFalse(
      try RSAPSS.verify(
        signature: mutated.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      ))

    do {
      _ = try RSAPSS.verify(
        signature: modulus.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: 32
      )
      XCTFail("a signature equal to the modulus was accepted")
    } catch {
      XCTAssertEqual(error, .nonCanonicalEncoding)
    }

    do {
      _ = try RSAPSS.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha256,
        saltLength: Int.max
      )
      XCTFail("an overflowing salt length was accepted")
    } catch {
      XCTAssertEqual(error, .invalidLength(expected: 222, actual: Int.max))
    }
  }

  func testSHA384AndSHA512PSSVerification() throws {
    let modulus = bytes(
      "CE077FDA0AA49392CD4E8DC4E8A87B8DEFD1735B326EFC6A0DA8640EC289163D3326AF04FE8929981BB3B2CF0DC8799A52FA1704156B5D3720DB446275405BE0FC887411608AE337254C08665D5BC92A2A544B8B6BB2B8F1DA8DED8231E6EFD91E746048C5C39337C96AD9206B296ED47EE92E0A7318A48BE6D29010727ECDA037A12A896F900784C551F92EA5FAAD9586B3E5E185E03C2901676FC4CAC72B830ED589E9A03085A3CBC495116E22DA367AC8033AFB54D07EF3579FD538CC390704475B16F25CC2547586152C9F7B31980BD75BC3BB29B5296005C458139A0FEB8488A47787ED046DC5FAA259C02D5938C0EE473B2E9068F20EF355F90B6A3E85"
    )
    let sha384Digest = bytes(
      "FAD790053DFFC263A8BC39A48D1AABC8D1A3B245CFFB91F27D3F07F7275139DAA6A093E3FC1F863B74C87B80EBD550DC"
    )
    let sha384Signature = bytes(
      "68C92F9A5A144E114D8039BFEDC9BAAE0400CE6FB4987922B6B511A4E063D66A7A6D41DC24785A32F05099B08571F6E886DDFAF58537C3A04BE573F41802DD8773408138402F52C2CF2CAC6BE3AA258F9C524AE923886E944DC7C79BB2167BF6BC9EE92C7FFD99D8A7FD107D34678725D8A931E3E2F287EE336FD246932B220EA1E429FC495636D322F7B525BCBFA291EDA8818C6D9744D1765A1F5DEFCDF70647ADEE21B1B54A604D91FEC3B956585CAE31ABB05D3BA357339FDEA47D0BE74EF7D28BC0891963DAB80D564EA7820EBFDEBFFA70962DA98CBB5A3D0239FCDAD88642AED988BE1824217EC76786F571D28D24A5ADF561B89E54D9AD6DC2C1D121"
    )
    let sha512Digest = bytes(
      "C6BB67619D83A9CA62CB854F8E895C858AE80C6A846A4E93DDEE64A52255DC6A254843CDA8F00B446790DC4FED078F92DD0E943817C819ABE99C9344320D9E61"
    )
    let sha512Signature = bytes(
      "79496484C1BFDD2726054D2CDABC0DDBCE5732720364B8C08C2C56B6D6E355D356FAB726C809C709CC4629F6A7E6A859554FA3E844A9595193257E98F6FBB D102DFF826047796194D2D4DBA65F94F22141F43C116614C7C1BC669A5D6021ECD70C3F0EC6E01C550863B19EB81DC2FB43C162E9CC5FA5789BDD9DA78DFF81C349A1D4BCF451A5D84530DC95D3EAD452AC03893684DECB3A3B422BBA433736E1CEB92E3391B334CB63AA3DA75D8656DEBEEE A0BF7EBC698D09DAE42455494E4437BE051525F9B9012DECEE4DD4E2704F13E639DCE6E60266676E0E9DB52227BA72DD85CC009F02CE31C116DC7E79CDF1D3380DD9F9DCBFD09E6952853E43930F46"
        .replacing(" ", with: "")
    )
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)
    XCTAssertTrue(
      try RSAPSS.verify(
        signature: sha384Signature.span, messageHash: sha384Digest.span, publicKey: key,
        hash: .sha384, saltLength: 48))
    XCTAssertTrue(
      try RSAPSS.verify(
        signature: sha512Signature.span, messageHash: sha512Digest.span, publicKey: key,
        hash: .sha512, saltLength: 64))

    var mutatedSHA384 = sha384Signature
    mutatedSHA384[mutatedSHA384.count / 2] ^= 0x80
    XCTAssertFalse(
      try RSAPSS.verify(
        signature: mutatedSHA384.span,
        messageHash: sha384Digest.span,
        publicKey: key,
        hash: .sha384,
        saltLength: 48
      ))

    var mutatedSHA512 = sha512Signature
    mutatedSHA512[mutatedSHA512.count / 2] ^= 0x80
    XCTAssertFalse(
      try RSAPSS.verify(
        signature: mutatedSHA512.span,
        messageHash: sha512Digest.span,
        publicKey: key,
        hash: .sha512,
        saltLength: 64
      ))
  }

  func testSHA512PSSVerificationAtMaximumModulusSize() throws {
    let modulus = bytes(
      "C136E42D2DF6BECCA3412CB0AAD3251FC4727104EBA54F2DB1C301B2B8EBDAF0"
        + "DE701CD1EA9E5A1FC2401ECC9F3E928435B9006BAD9E8DFF2D344F8E449F1511"
        + "C0EB2ECD18A7166211C9F96FBDBC260DC0DD5D4BEDCB3648C019009C6BF86FD0"
        + "4076D999A31BA3A2EEBBD9436BCE880495470AD079CC41DB5A5D19A8F5FF7791"
        + "9B989BB9C617D0BD63A996A7898F6D52569272C7B3B76693967D89750B95FA29"
        + "06D2EE247BEEEAB5279C3679CD52A54770EA66EE8B69902A18AC5CAB2FA08152"
        + "0C8B0C697D42D28F5F155276F8FAB714EE0A18E2458C03626BE81F93E1EFC17F"
        + "EF43A528C3CC229584303645812FAF8170E29261C470698D12AD257EC9A94160"
        + "8629A79B55BB88CFB33BBE6031849C534CCC1E504FD905232E323FF9EECD6911"
        + "5FABA360C19E338DD7EA00C57A212928FB2EF365A7C9539BA7D280D0FC879FE0"
        + "CF7AA189609D299FCD05498E41C30152C4509307545CDFD1AA5F11F63BB44BE4"
        + "2517ACE0D1AF045CF7E341C67D0F136AD8424F86AC778CC5964D976B47DB2EB9"
        + "FD22266367F99D6DA762B9AEF18532FDCB6F848E21419D779933304214B5A7E3"
        + "1EFF7E78AE0922E66E476253333E3D60E948B0700271F386957B012456247454"
        + "B292C6ABB3FEB033FF5CC669314B480559A148825371D0D2382FF934AA8C862F"
        + "95BDF9EA227677BE4F4B2D451B879D3A4A3A3AC845E5E87F1A1E3D70A91BC441"
    )
    let digest = bytes(
      "CF33F109DA8CB5D64DCF51465B6A8175E518427F8BF37DFE5A12D634024E1401"
        + "0639282CDF69DE8D439A1CFE0D3AECEE7B32B56251B7EC49FA426D51C13763A8"
    )
    let signature = bytes(
      "47A7691A8765388628A7370F0064FFB0AA8AC1AFA25150D9803BB7B6E9217CEF"
        + "79C14EEEF5A2F72DF14F23B21B5B8B11B6CE90281280762C75D0DA9E06CABADE"
        + "5EAFF3666F9E11C0931F794A6E2814A8475E0850780C61A0AAB2B636A4270477"
        + "17944E4BE93DB757DF5EF8B261CAB0D10CB3D35DCB47ACD20BD567727A22BB0C"
        + "BCB8C0D966CB80B97AB6F4EB4E7C0FA0DCAF44404571641262247E3635DA35BD"
        + "5B7BFD79FA43CDAE1E7FA862F38B71DE2E98B39105A6ACD7C75C11F1F3AA0FE6"
        + "18A6448C4A6E2093A0C2C270A6FC3463D8AD7FCEF8C8A1A53244DD638E2F7026"
        + "D0A1DA4B5F4DE55A863B383387A0C20135B55A07F5329BB4D7F3769DF1077FD0"
        + "E2B7226C286BCCBF2F4DB98F2120B1CC177390468EF8A82DC21C9A0E05E6EC12"
        + "446910D85E5E2877B6792D78E3C22BE89688A80CD6A1844C623C1BE975AC3337"
        + "ED1DD0FE1014BFBECE6B4ACE04F8864FD9709415B2F11BB8169B24CBB895FFBA"
        + "238EA06C9AC1E36EE73D0BBDDCC0098D690A6B20C59C338BA346C9EB57F6A876"
        + "461B7F0EEB8668F10CFC001064A1CA693647E0FBAF4C6FFA8B2AA9F20A35EA80"
        + "6C1DC57EFE967513313BF8BE55CC79094A52C8E6EAC3C21C953BC59A2B01FFE2"
        + "A90B19735F4FEB69FF0621876CF69A3257BCE5A0F7F2B0CFD725425C869B6129"
        + "013B77596BBCA84DF7B39077E9420182CC36DBF3D118474114175A32E7B51468"
    )
    let key = try RSAPublicKey(modulus: modulus.span, exponent: 65_537)

    XCTAssertTrue(
      try RSAPSS.verify(
        signature: signature.span,
        messageHash: digest.span,
        publicKey: key,
        hash: .sha512,
        saltLength: 64
      ))
  }

  func testPublicKeyAndInputBoundaries() throws {
    var validModulus = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: RSAPublicKey.minimumModulusByteCount
    )
    validModulus[validModulus.count - 1] |= 1
    XCTAssertNoThrow(try RSAPublicKey(modulus: validModulus.span, exponent: 65_537))

    var shortModulus = validModulus
    shortModulus.removeLast()
    assertCryptoInputError(.invalidLength(expected: 256, actual: 255)) {
      _ = try RSAPublicKey(modulus: shortModulus.span, exponent: 65_537)
    }

    var longModulus = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: RSAPublicKey.maximumModulusByteCount + 1
    )
    longModulus[longModulus.count - 1] |= 1
    assertCryptoInputError(.invalidLength(expected: 256, actual: 513)) {
      _ = try RSAPublicKey(modulus: longModulus.span, exponent: 65_537)
    }

    var leadingZero = validModulus
    leadingZero[0] = 0
    assertCryptoInputError(.nonCanonicalEncoding) {
      _ = try RSAPublicKey(modulus: leadingZero.span, exponent: 65_537)
    }

    var evenModulus = validModulus
    evenModulus[evenModulus.count - 1] &= 0xFE
    assertCryptoInputError(.nonCanonicalEncoding) {
      _ = try RSAPublicKey(modulus: evenModulus.span, exponent: 65_537)
    }

    for invalidExponent: UInt64 in [0, 1, 2, 4, UInt64(Int.max) + 2] {
      assertCryptoInputError(.nonCanonicalEncoding) {
        _ = try RSAPublicKey(
          modulus: validModulus.span,
          exponent: invalidExponent
        )
      }
    }
  }

  func testMontgomeryPowerMatchesUInt64Reference() {
    var generator: UInt64 = 0x9E37_79B9_7F4A_7C15
    var iteration = 0
    while iteration < 512 {
      generator = generator &* 6_364_136_223_846_793_005 &+ 1
      let modulus = (generator | 1 | (UInt64(1) << 63))
      generator = generator &* 6_364_136_223_846_793_005 &+ 1
      let base = generator % modulus
      generator = generator &* 6_364_136_223_846_793_005 &+ 1
      let exponent = generator & 0xFFFF

      let actual = RSAUInt.modularPower(
        rsaUInt(base),
        exponent: exponent,
        modulus: rsaUInt(modulus)
      )
      XCTAssertEqual(
        uint64(actual),
        modularPower(
          base,
          exponent: exponent,
          modulus: modulus
        ))
      iteration += 1
    }
  }

  private func assertCryptoInputError(
    _ expected: CryptoInputError,
    operation: () throws -> Void
  ) {
    do {
      try operation()
      XCTFail("operation unexpectedly succeeded")
    } catch let error as CryptoInputError {
      XCTAssertEqual(error, expected)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
  }

  private func rsaUInt(_ value: UInt64) -> RSAUInt {
    RSAUInt(words: [
      UInt32(truncatingIfNeeded: value),
      UInt32(truncatingIfNeeded: value >> 32),
    ])
  }

  private func uint64(_ value: RSAUInt) -> UInt64 {
    UInt64(value.words[0]) | UInt64(value.words[1]) << 32
  }

  private func modularPower(
    _ base: UInt64,
    exponent: UInt64,
    modulus: UInt64
  ) -> UInt64 {
    var result: UInt64 = 1
    var value = base % modulus
    var exponent = exponent
    while exponent != 0 {
      if exponent & 1 != 0 {
        result = modularMultiply(result, value, modulus: modulus)
      }
      exponent >>= 1
      if exponent != 0 {
        value = modularMultiply(value, value, modulus: modulus)
      }
    }
    return result
  }

  private func modularMultiply(
    _ lhs: UInt64,
    _ rhs: UInt64,
    modulus: UInt64
  ) -> UInt64 {
    let product = lhs.multipliedFullWidth(by: rhs)
    return modulus.dividingFullWidth(product).remainder
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
}
