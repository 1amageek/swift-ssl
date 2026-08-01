import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class MLKEMTests: XCTestCase {
  func testMLKEM768KeyGenerationMatchesNISTACVPFIPS203() throws {
    let pair = try MLKEM768.keyPair(
      d: bytes("E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0").span,
      z: bytes("1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0").span
    )
    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("4158F6AFB5E516C99F1DA07DA8C651348422B17C1F4E9A08AD73FB1F91249B3E")
    )
    let privateDigest = try pair.privateKey.withBorrowedBytes { try digest($0) }
    XCTAssertEqual(
      privateDigest,
      bytes("7AAB35839207F72B310ABE36E2DAA1CC7FF6F7FA8941E439967CD47D9B437079")
    )
  }

  func testMLKEM1024KeyGenerationMatchesNISTACVPFIPS203() throws {
    let pair = try MLKEM1024.keyPair(
      d: bytes("F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009").span,
      z: bytes("35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275").span
    )
    XCTAssertEqual(
      try digest(pair.publicKey.span),
      bytes("B78619E4FCEEEB86DEE3FEDB945ECA6DA61DAE312771EF8FA871951D391BD7B6")
    )
    let privateDigest = try pair.privateKey.withBorrowedBytes { try digest($0) }
    XCTAssertEqual(
      privateDigest,
      bytes("925ED6F1CF0379EDE29D8209432D6E08C73ED0423883FEBF85416343F4FA1F86")
    )
  }

  func testMLKEM768RoundTripAndImplicitRejection() throws {
    let pair = try MLKEM768.keyPair(
      d: bytes("E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0").span,
      z: bytes("1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0").span
    )
    let result = try MLKEM768.encapsulate(
      to: pair.publicKey,
      message: bytes("DE00DF8311D05E830C71B568DA4CF0F0C7F458D94139DE92D3C5F21C3CA48AD8").span
    )
    let expected = result.sharedSecret.withBorrowedBytes { copy($0) }
    let recovered = try MLKEM768.decapsulate(
      result.encapsulation,
      using: pair.privateKey
    )
    XCTAssertEqual(recovered.withBorrowedBytes { copy($0) }, expected)

    var mutatedBytes = copy(result.encapsulation.span)
    mutatedBytes[mutatedBytes.count / 2] ^= 0x80
    let mutated = try MLKEM768.Encapsulation(bytes: mutatedBytes.span)
    let rejected = try MLKEM768.decapsulate(mutated, using: pair.privateKey)
    XCTAssertNotEqual(rejected.withBorrowedBytes { copy($0) }, expected)
  }

  func testMLKEM768EncapsulationMatchesNISTACVPFIPS203TR1() throws {
    let publicKey = try MLKEM768.PublicKey(
      bytes: bytes(
        """
        50D5BF5B073150939F269996B4D78B61EAA7EE8B862F51B598E953C92B7E4A466D27093E6D2041FA8B646F2768A2D8A0E602A54BD54E9C139545DC6F2BF90815C158CCB237A51CA3E413A5F33950921BA8FC7115F38099F2851D87074A528335AD1A3221D48BEF0B632F3A11FB9B3DDFFA5A5A56B2DA8AA6DB8A1730989DADF4B08ABC2D5A9119979303D329A759C314E19801D34438BA3907FC40472F3602F86C27B77A99768794EA15BC99888FCFFAB152A2BC3CB961C14A89CD9A3B2C68487B243BE5FA316E76756E237E92451F025BC59068772749303E3C1218104538F26EAF6C2A32CA54E1154BF47A7A546CC66840037D8962C17B11F276B250CA23B1620B61B26F6BC85CD5E034F18622E17BB6BB07C43C83550CB39443E8652FA41725B7781A2B42E20A921006951A8492EF9610313A3079B4796F69375F37373BC35FA7BCAB1ABBAD48034EB8E988D0C57097322567DA7A5BE07FB878835CA03302169B8BDAB8ACDC7B65BA788B5B5D2A09CBA88125D4351AE05B0B1FE1A6FA95BFD90554233BBB8622C5BD40AB57250BDDF50A8FF6CCFA6ACEC6430208994ACADB70D0E09B70683F0B95AB867ABD2B3673629386B6E12E39699471D520B877B153D2B3B49004B80545DB30BF4D1BCA8832A9C8611BF311BA465CA0F5448A3326B9E6074C68A5189F8BA4A3E88D84C3C2D0820325A2531A1227F2529CCA1B9E4D32917C22AA1350C63955CBD1E6B81768B66BCB292AA9CBA26505F4DB2C670581D9F632C42339CCC09DD3516C3817AC86E23214A71484822F6EA20216B1CC29B946C47A77BEA53DA8975073B68E9949411AE7B64E687FA99193ADD2BB20249FA15A6F06795CF03995F5DC732EF3C753E58F3E9AB497565A37027AB6466FD5C2BC451B4EB140483891718321CB833231222A805F5740D3E85DC4A94B02E11D9ADB814B109F657CCE418309C1F19A3D495878F86D177B62A5C58E6B3A12A8FC9133778E3FC68C24136D65B5857794A54C93B17BD6625AF80D62106080074C181A27D07CC8E7DBCE8A792E556964A8862F7E67544B9C62110040C37CA6FAC829F630416A9852F3F452BC994755A04E8CF3852FA3921C27369AB8AFFF889E15B33564A9C075A0CD854262B7F0544D769CE0A159A42975CB1A34EEB71331FA6F49CC03F6507DA8AA5D9CF59455BB375C324E44166BEA82AD42633140E2C149785310E4B4CF61B75F1037BA43167B39907497A0EA718DBD674A8856CB9972A245FA6B8026097F05B05A536F82835550B931251465F945377C172C325A13AA2765A2E6395B7ABF9D277C41CA85006DC35B3738CA68C16A17CB5035345D4B2EED0B732C993E1FD42484B6A252B8472BB3092FD986EA9B66A1F37B1B856C33D78B9FBC8D4ED0C66F78247EF18FC1A2AAB72951BC810D8F8646CCD983FCE99AA3DB8D27E00870939389309E10785DE66B76466501451B43BEB63550C803A40AA784B95A26890A24407BD7F084B869BFEC4C2E02266B0E5478420405FA103E5D41A723755FF58CABFD94A75CD00DA6A0B740A8652907BC78C43E1E948157E95DBF6AC165CC203FB4AA8D78A51E887F9CF8870197BCC5F8C1F4AB2311364DBAD289C304864D325B502C7FAA7C6250F893A432C427B42977984F824AFA615D0084456696045D9F6F
        """
      ).span)
    let result = try MLKEM768.encapsulate(
      to: publicKey,
      message: bytes("DE00DF8311D05E830C71B568DA4CF0F0C7F458D94139DE92D3C5F21C3CA48AD8").span
    )
    XCTAssertEqual(
      result.sharedSecret.withBorrowedBytes { copy($0) },
      bytes("2EF8DE64BFBFEB974EC48E8FB839FA16ED5B848D573429AD906493818481F075")
    )
    XCTAssertEqual(
      try digest(result.encapsulation.span),
      bytes("9C55953BC189C554E9307E83243A960B479161ACD06C183F238D3BBA3666459A")
    )
  }

  func testMLKEM1024RoundTrip() throws {
    let pair = try MLKEM1024.keyPair(
      d: bytes("F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009").span,
      z: bytes("35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275").span
    )
    let result = try MLKEM1024.encapsulate(
      to: pair.publicKey,
      message: bytes("8FB8906C16C4D8190F59C254B1EAA537D46A71E864F2ABAC5CC87B79420CA762").span
    )
    let expected = result.sharedSecret.withBorrowedBytes { copy($0) }
    let recovered = try MLKEM1024.decapsulate(
      result.encapsulation,
      using: pair.privateKey
    )
    XCTAssertEqual(recovered.withBorrowedBytes { copy($0) }, expected)
  }

  func testMLKEMInputValidationRejectsNonCanonicalAndCorruptKeys() throws {
    var invalidPublic = ContiguousArray<UInt8>(repeating: 0, count: MLKEM768.PublicKey.byteCount)
    invalidPublic[0] = 0xFF
    invalidPublic[1] = 0x0F
    XCTAssertThrowsError(try MLKEM768.PublicKey(bytes: invalidPublic.span)) { error in
      XCTAssertEqual(error as? KEMError, .invalidPublicKeyEncoding)
    }

    let pair = try MLKEM768.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
    )
    var privateBytes = pair.privateKey.withBorrowedBytes { copy($0) }
    privateBytes[privateBytes.count - 33] ^= 1
    do {
      let unused = try MLKEM768.PrivateKey(bytes: privateBytes.span)
      _ = consume unused
      XCTFail("corrupt decapsulation key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }

    var nonCanonicalPrivate = pair.privateKey.withBorrowedBytes { copy($0) }
    nonCanonicalPrivate[0] = 0xFF
    nonCanonicalPrivate[1] |= 0x0F
    do {
      let unused = try MLKEM768.PrivateKey(bytes: nonCanonicalPrivate.span)
      _ = consume unused
      XCTFail("non-canonical decapsulation key was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPrivateKeyEncoding)
    }
  }

  func testMLKEM768InPlaceOperationsMatchOwnedResults() throws {
    let pair = try MLKEM768.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x31, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x42, count: 32).span
    )
    let message = ContiguousArray<UInt8>(repeating: 0x73, count: 32)
    let owned = try MLKEM768.encapsulate(to: pair.publicKey, message: message.span)
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.sharedSecretByteCount
    )
    var encapsulationOutput = encapsulation.mutableSpan
    var secretOutput = sharedSecret.mutableSpan
    try MLKEM768.encapsulate(
      to: pair.publicKey,
      using: FixedEntropy(bytes: message),
      into: &encapsulationOutput,
      sharedSecret: &secretOutput
    )

    XCTAssertEqual(encapsulation, copy(owned.encapsulation.span))
    XCTAssertEqual(
      sharedSecret,
      owned.sharedSecret.withBorrowedBytes { copy($0) }
    )

    var recovered = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.sharedSecretByteCount
    )
    var recoveredOutput = recovered.mutableSpan
    try MLKEM768.decapsulate(
      encapsulation.span,
      using: pair.privateKey,
      into: &recoveredOutput
    )
    XCTAssertEqual(recovered, sharedSecret)
  }

  func testMLKEM1024InPlaceOperationsRoundTrip() throws {
    let pair = try MLKEM1024.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x51, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x62, count: 32).span
    )
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.sharedSecretByteCount
    )
    var encapsulationOutput = encapsulation.mutableSpan
    var secretOutput = sharedSecret.mutableSpan
    try MLKEM1024.encapsulate(
      to: pair.publicKey,
      using: FixedEntropy(bytes: ContiguousArray(repeating: 0x74, count: 32)),
      into: &encapsulationOutput,
      sharedSecret: &secretOutput
    )

    var recovered = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM1024.sharedSecretByteCount
    )
    var recoveredOutput = recovered.mutableSpan
    try MLKEM1024.decapsulate(
      encapsulation.span,
      using: pair.privateKey,
      into: &recoveredOutput
    )
    XCTAssertEqual(recovered, sharedSecret)
  }

  func testMLKEM768EncodedPublicKeyInPlaceRoundTrip() throws {
    let pair = try MLKEM768.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x21, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x32, count: 32).span
    )
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM768.sharedSecretByteCount
    )
    var encapsulationOutput = encapsulation.mutableSpan
    var sharedSecretOutput = sharedSecret.mutableSpan
    try MLKEM768.encapsulate(
      toEncodedPublicKey: pair.publicKey.span,
      using: FixedEntropy(bytes: ContiguousArray(repeating: 0x43, count: 32)),
      into: &encapsulationOutput,
      sharedSecret: &sharedSecretOutput
    )

    var recovered = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var recoveredOutput = recovered.mutableSpan
    try MLKEM768.decapsulate(
      encapsulation.span,
      using: pair.privateKey,
      into: &recoveredOutput
    )
    XCTAssertEqual(recovered, sharedSecret)
  }

  func testMLKEM1024EncodedPublicKeyRejectsInvalidLengthWithoutMutation() throws {
    let shortPublicKey = ContiguousArray<UInt8>(
      repeating: 0,
      count: MLKEM1024.PublicKey.byteCount - 1
    )
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM1024.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM1024.sharedSecretByteCount
    )
    let originalEncapsulation = encapsulation
    let originalSharedSecret = sharedSecret
    do {
      var encapsulationOutput = encapsulation.mutableSpan
      var sharedSecretOutput = sharedSecret.mutableSpan
      try MLKEM1024.encapsulate(
        toEncodedPublicKey: shortPublicKey.span,
        using: FixedEntropy(bytes: ContiguousArray(repeating: 0x63, count: 32)),
        into: &encapsulationOutput,
        sharedSecret: &sharedSecretOutput
      )
      XCTFail("encoded-key encapsulation accepted a short public key")
    } catch {
      XCTAssertEqual(
        error,
        .invalidPublicKeyLength(
          expected: MLKEM1024.PublicKey.byteCount,
          actual: MLKEM1024.PublicKey.byteCount - 1
        )
      )
    }
    XCTAssertEqual(encapsulation, originalEncapsulation)
    XCTAssertEqual(sharedSecret, originalSharedSecret)
  }

  func testMLKEMInPlaceLengthFailuresDoNotModifyOutputs() throws {
    let pair = try MLKEM768.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x11, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x22, count: 32).span
    )
    let entropy = FixedEntropy(bytes: ContiguousArray(repeating: 0x33, count: 32))
    var shortEncapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.encapsulationByteCount - 1
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.sharedSecretByteCount
    )
    let originalShortEncapsulation = shortEncapsulation
    let originalSharedSecret = sharedSecret
    do {
      var encapsulationOutput = shortEncapsulation.mutableSpan
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM768.encapsulate(
        to: pair.publicKey,
        using: entropy,
        into: &encapsulationOutput,
        sharedSecret: &secretOutput
      )
      XCTFail("in-place encapsulation accepted a short output")
    } catch {
      XCTAssertEqual(
        error,
        .invalidEncapsulationLength(
          expected: MLKEM768.encapsulationByteCount,
          actual: MLKEM768.encapsulationByteCount - 1
        )
      )
    }
    XCTAssertEqual(shortEncapsulation, originalShortEncapsulation)
    XCTAssertEqual(sharedSecret, originalSharedSecret)

    var fullEncapsulation = ContiguousArray<UInt8>(
      repeating: 0xC3,
      count: MLKEM768.encapsulationByteCount
    )
    var shortEncapsulationSecret = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM768.sharedSecretByteCount - 1
    )
    let originalFullEncapsulation = fullEncapsulation
    let originalShortEncapsulationSecret = shortEncapsulationSecret
    do {
      var encapsulationOutput = fullEncapsulation.mutableSpan
      var secretOutput = shortEncapsulationSecret.mutableSpan
      try MLKEM768.encapsulate(
        to: pair.publicKey,
        using: entropy,
        into: &encapsulationOutput,
        sharedSecret: &secretOutput
      )
      XCTFail("in-place encapsulation accepted a short shared-secret output")
    } catch {
      XCTAssertEqual(
        error,
        .invalidSharedSecretLength(
          expected: MLKEM768.sharedSecretByteCount,
          actual: MLKEM768.sharedSecretByteCount - 1
        )
      )
    }
    XCTAssertEqual(fullEncapsulation, originalFullEncapsulation)
    XCTAssertEqual(shortEncapsulationSecret, originalShortEncapsulationSecret)

    let encapsulated = try MLKEM768.encapsulate(to: pair.publicKey, using: entropy)
    var decapsulationOutput = ContiguousArray<UInt8>(
      repeating: 0x96,
      count: MLKEM768.sharedSecretByteCount
    )
    let originalDecapsulationOutput = decapsulationOutput
    do {
      var output = decapsulationOutput.mutableSpan
      try MLKEM768.decapsulate(
        encapsulated.encapsulation.span.extracting(
          0..<(MLKEM768.encapsulationByteCount - 1)
        ),
        using: pair.privateKey,
        into: &output
      )
      XCTFail("in-place decapsulation accepted a short encapsulation")
    } catch {
      XCTAssertEqual(
        error,
        .invalidEncapsulationLength(
          expected: MLKEM768.encapsulationByteCount,
          actual: MLKEM768.encapsulationByteCount - 1
        )
      )
    }
    XCTAssertEqual(decapsulationOutput, originalDecapsulationOutput)

    var shortSecret = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM768.sharedSecretByteCount - 1
    )
    let originalShortSecret = shortSecret
    do {
      var output = shortSecret.mutableSpan
      try MLKEM768.decapsulate(
        encapsulated.encapsulation.span,
        using: pair.privateKey,
        into: &output
      )
      XCTFail("in-place decapsulation accepted a short shared-secret output")
    } catch {
      XCTAssertEqual(
        error,
        .invalidSharedSecretLength(
          expected: MLKEM768.sharedSecretByteCount,
          actual: MLKEM768.sharedSecretByteCount - 1
        )
      )
    }
    XCTAssertEqual(shortSecret, originalShortSecret)
  }

  func testMLKEMInPlaceEntropyFailureDoesNotModifyOutputs() throws {
    let pair = try MLKEM768.keyPair(
      d: ContiguousArray<UInt8>(repeating: 0x41, count: 32).span,
      z: ContiguousArray<UInt8>(repeating: 0x52, count: 32).span
    )
    var encapsulation = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: MLKEM768.encapsulationByteCount
    )
    var sharedSecret = ContiguousArray<UInt8>(
      repeating: 0x5A,
      count: MLKEM768.sharedSecretByteCount
    )
    let originalEncapsulation = encapsulation
    let originalSharedSecret = sharedSecret

    do {
      var encapsulationOutput = encapsulation.mutableSpan
      var secretOutput = sharedSecret.mutableSpan
      try MLKEM768.encapsulate(
        to: pair.publicKey,
        using: FailingEntropy(),
        into: &encapsulationOutput,
        sharedSecret: &secretOutput
      )
      XCTFail("in-place encapsulation accepted an entropy failure")
    } catch {
      XCTAssertEqual(error, .entropy(.sourceRejected))
    }

    XCTAssertEqual(encapsulation, originalEncapsulation)
    XCTAssertEqual(sharedSecret, originalSharedSecret)
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
        destination[0] = 0xC3
      }
      throw .sourceRejected
    }
  }

  private func digest(_ input: Span<UInt8>) throws -> ContiguousArray<UInt8> {
    var output = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
    var destination = output.mutableSpan
    try SHA256.hash(input, into: &destination)
    return output
  }

  private func copy(_ input: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(input.count)
    var index = 0
    while index < input.count {
      result.append(input[index])
      index += 1
    }
    return result
  }

  private func bytes(_ value: String) -> ContiguousArray<UInt8> {
    let value = value.filter { $0.isHexDigit }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      result.append(UInt8(value[index..<next], radix: 16)!)
      index = next
    }
    return result
  }
}
