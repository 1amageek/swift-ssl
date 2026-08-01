import SwiftSSLCore
import XCTest

@testable import SwiftSSLCrypto

final class HPKETests: XCTestCase {
  func testRFC9180X25519ChaChaBaseVector() throws {
    let recipientPrivate = try X25519PrivateKey(
      bytes: bytes(
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"
      ).span)
    let entropy = FixedEntropy(
      bytes: bytes(
        "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"
      ))
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    var setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: entropy
    )
    XCTAssertEqual(
      copy(setup.encapsulation.span),
      Array(bytes("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"))
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var sender = setup.takeContext()
    let plaintext = bytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad = bytes("436f756e742d30")
    let ciphertext = try sender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(
      copy(ciphertext.span),
      Array(
        bytes(
          "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
        ))
    )
    let opened = try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(copy(opened.span), Array(plaintext))
    let exported = try sender.export(ContiguousArray<UInt8>().span, length: 32)
    let exportedBytes = exported.withBorrowedBytes { copy($0) }
    XCTAssertEqual(
      exportedBytes,
      Array(bytes("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"))
    )
    let emptyExport = try sender.export(ContiguousArray<UInt8>().span, length: 0)
    XCTAssertEqual(emptyExport.count, 0)
    XCTAssertEqual(emptyExport.withBorrowedBytes { $0.count }, 0)
  }

  func testRFC9180X25519ChaChaAuthVector() throws {
    let recipientPrivate = try X25519PrivateKey(
      bytes: bytes(
        "3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82"
      ).span)
    let senderPrivate = try X25519PrivateKey(
      bytes: bytes(
        "2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05"
      ).span)
    let entropy = FixedEntropy(
      bytes: bytes(
        "c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13"
      ))
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    var setup = try HPKEX25519.setupAuthSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      senderPrivateKey: senderPrivate,
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: entropy
    )
    XCTAssertEqual(
      copy(setup.encapsulation.span),
      Array(bytes("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e"))
    )
    var recipient = try HPKEX25519.setupAuthRecipient(
      encapsulation: setup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey(),
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var sender = setup.takeContext()
    let plaintext = bytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad = bytes("436f756e742d30")
    let ciphertext = try sender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(
      copy(ciphertext.span),
      Array(
        bytes(
          "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf"
        ))
    )
    let opened = try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(copy(opened.span), Array(plaintext))
    let exported = try sender.export(ContiguousArray<UInt8>().span, length: 32)
    let exportedBytes = exported.withBorrowedBytes { copy($0) }
    XCTAssertEqual(
      exportedBytes,
      Array(bytes("070cffafd89b67b7f0eeb800235303a223e6ff9d1e774dce8eac585c8688c872"))
    )
  }

  func testRFC9180X25519ChaChaPSKVector() throws {
    let recipientPrivate = try X25519PrivateKey(
      bytes: bytes(
        "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879"
      ).span)
    let psk = bytes(
      "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"
    )
    let pskID = bytes("456e6e796e20447572696e206172616e204d6f726961")
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    let entropy = FixedEntropy(
      bytes: bytes(
        "0c35fdf49df7aa01cd330049332c40411ebba36e0c718ebc3edf5845795f6321"
      ))
    var setup = try HPKEX25519.setupPSKSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: entropy
    )
    XCTAssertEqual(
      copy(setup.encapsulation.span),
      Array(bytes("2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04"))
    )
    var recipient = try HPKEX25519.setupPSKRecipient(
      encapsulation: setup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var sender = setup.takeContext()
    let plaintext = bytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad = bytes("436f756e742d30")
    let ciphertext = try sender.seal(plaintext: plaintext.span, authenticatedData: aad.span)
    XCTAssertEqual(
      copy(ciphertext.span),
      Array(
        bytes(
          "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff"
        ))
    )
    let opened = try recipient.open(ciphertext: ciphertext.span, authenticatedData: aad.span)
    XCTAssertEqual(copy(opened.span), Array(plaintext))
    let exported = try sender.export(ContiguousArray<UInt8>().span, length: 32)
    XCTAssertEqual(
      exported.withBorrowedBytes { copy($0) },
      Array(bytes("813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40"))
    )
  }

  func testRFC9180X25519ChaChaAuthPSKVector() throws {
    let recipientPrivate = try X25519PrivateKey(
      bytes: bytes(
        "7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c"
      ).span)
    let senderPrivate = try X25519PrivateKey(
      bytes: bytes(
        "90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418"
      ).span)
    let psk = bytes(
      "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"
    )
    let pskID = bytes("456e6e796e20447572696e206172616e204d6f726961")
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    let entropy = FixedEntropy(
      bytes: bytes(
        "5e6dd73e82b856339572b7245d3cbb073a7561c0bee52873490e305cbb710410"
      ))
    var setup = try HPKEX25519.setupAuthPSKSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      senderPrivateKey: senderPrivate,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: entropy
    )
    XCTAssertEqual(
      copy(setup.encapsulation.span),
      Array(bytes("656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02"))
    )
    var recipient = try HPKEX25519.setupAuthPSKRecipient(
      encapsulation: setup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey(),
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var sender = setup.takeContext()
    let plaintext = bytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad = bytes("436f756e742d30")
    let ciphertext = try sender.seal(plaintext: plaintext.span, authenticatedData: aad.span)
    XCTAssertEqual(
      copy(ciphertext.span),
      Array(
        bytes(
          "9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597"
        ))
    )
    let opened = try recipient.open(ciphertext: ciphertext.span, authenticatedData: aad.span)
    XCTAssertEqual(copy(opened.span), Array(plaintext))
    let exported = try sender.export(ContiguousArray<UInt8>().span, length: 32)
    XCTAssertEqual(
      exported.withBorrowedBytes { copy($0) },
      Array(bytes("c23ebd4e7a0ad06a5dddf779f65004ce9481069ce0f0e6dd51a04539ddcbd5cd"))
    )
  }

  func testBaseRoundTripCoversAllKDFAndAEADChoices() throws {
    let recipientPrivate = try X25519PrivateKey(bytes: bytes(repeating: 0x11, count: 32).span)
    let info = bytes("00112233445566778899aabbccddeeff")
    let plaintext = bytes("706c61696e74657874")
    let aad = bytes("616164")
    let kdFs: [HPKEKDF] = [.sha256, .sha384, .sha512]
    let aeads: [HPKEAEAD] = [.aes128GCM, .aes256GCM, .chaCha20Poly1305]

    for kdf in kdFs {
      for aead in aeads {
        let entropy = FixedEntropy(bytes: bytes(repeating: 0x22, count: 32))
        var setup = try HPKEX25519.setupBaseSender(
          recipientPublicKey: recipientPrivate.publicKey(),
          info: info.span,
          kdf: kdf,
          aead: aead,
          using: entropy
        )
        var recipient = try HPKEX25519.setupBaseRecipient(
          encapsulation: setup.encapsulation.span,
          recipientPrivateKey: recipientPrivate,
          info: info.span,
          kdf: kdf,
          aead: aead
        )
        var sender = setup.takeContext()
        let ciphertext = try sender.seal(
          plaintext: plaintext.span,
          authenticatedData: aad.span
        )
        let opened = try recipient.open(
          ciphertext: ciphertext.span,
          authenticatedData: aad.span
        )
        XCTAssertEqual(copy(opened.span), Array(plaintext))
        let senderExport = try sender.export(bytes("01").span, length: 32)
        let recipientExport = try recipient.export(bytes("01").span, length: 32)
        let senderExportBytes = senderExport.withBorrowedBytes { copy($0) }
        let recipientExportBytes = recipientExport.withBorrowedBytes { copy($0) }
        XCTAssertEqual(senderExportBytes, recipientExportBytes)
        XCTAssertEqual(sender.sequenceNumber, 1)
        XCTAssertEqual(recipient.sequenceNumber, 1)
      }
    }
  }

  func testPSKRoundTripAndIdentityValidation() throws {
    let recipientPrivate = try X25519PrivateKey(bytes: bytes(repeating: 0x31, count: 32).span)
    let psk = bytes("000102030405060708090a0b0c0d0e0f")
    let pskID = bytes("746573742d70736b")
    let info = bytes("696e666f")
    let entropy = FixedEntropy(bytes: bytes(repeating: 0x32, count: 32))
    var setup = try HPKEX25519.setupPSKSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: entropy
    )
    let encapsulation = setup.encapsulation
    var recipient = try HPKEX25519.setupPSKRecipient(
      encapsulation: encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var sender = setup.takeContext()
    let ciphertext = try sender.seal(
      plaintext: bytes("7061796c6f6164").span,
      authenticatedData: bytes("616164").span
    )
    let opened = try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: bytes("616164").span
    )
    XCTAssertEqual(copy(opened.span), Array(bytes("7061796c6f6164")))

    do {
      _ = try HPKEX25519.setupPSKRecipient(
        encapsulation: encapsulation.span,
        recipientPrivateKey: recipientPrivate,
        info: info.span,
        psk: ContiguousArray<UInt8>().span,
        pskID: pskID.span,
        kdf: .sha256,
        aead: .chaCha20Poly1305
      )
      XCTFail("empty PSK was accepted")
    } catch {
      XCTAssertEqual(error, .invalidPseudorandomKey)
    }
  }

  func testAuthAndAuthPSKRoundTrips() throws {
    let recipientPrivate = try X25519PrivateKey(bytes: bytes(repeating: 0x41, count: 32).span)
    let senderPrivate = try X25519PrivateKey(bytes: bytes(repeating: 0x42, count: 32).span)
    let info = bytes("61757468")
    let psk = bytes("50534b2d736563726574")
    let pskID = bytes("70736b2d6964")
    let aad = bytes("616164")
    let plaintext = bytes("617574682d7061796c6f6164")

    var authSetup = try HPKEX25519.setupAuthSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      senderPrivateKey: senderPrivate,
      info: info.span,
      kdf: .sha384,
      aead: .aes256GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x43, count: 32))
    )
    var authRecipient = try HPKEX25519.setupAuthRecipient(
      encapsulation: authSetup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey(),
      info: info.span,
      kdf: .sha384,
      aead: .aes256GCM
    )
    var authSender = authSetup.takeContext()
    let authCiphertext = try authSender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    let authOpened = try authRecipient.open(
      ciphertext: authCiphertext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(copy(authOpened.span), Array(plaintext))

    var authPSKSetup = try HPKEX25519.setupAuthPSKSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      senderPrivateKey: senderPrivate,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha512,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x44, count: 32))
    )
    var authPSKRecipient = try HPKEX25519.setupAuthPSKRecipient(
      encapsulation: authPSKSetup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey(),
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha512,
      aead: .aes128GCM
    )
    var authPSKSender = authPSKSetup.takeContext()
    let authPSKCiphertext = try authPSKSender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    let authPSKOpened = try authPSKRecipient.open(
      ciphertext: authPSKCiphertext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(copy(authPSKOpened.span), Array(plaintext))
  }

  func testAuthenticationFailureDoesNotAdvanceRecipientSequence() throws {
    let recipientPrivate = try X25519PrivateKey(bytes: bytes(repeating: 0x51, count: 32).span)
    var setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey(),
      info: bytes("69").span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x52, count: 32))
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientPrivateKey: recipientPrivate,
      info: bytes("69").span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var sender = setup.takeContext()
    let ciphertext = try sender.seal(
      plaintext: bytes("706c61696e").span,
      authenticatedData: bytes("616164").span
    )
    var modified = ContiguousArray(copy(ciphertext.span))
    modified[modified.count - 1] ^= 1
    do {
      _ = try recipient.open(ciphertext: modified.span, authenticatedData: bytes("616164").span)
      XCTFail("modified ciphertext was accepted")
    } catch {
      XCTAssertEqual(error, .authenticatedCipher(.authenticationFailed))
    }
    XCTAssertEqual(recipient.sequenceNumber, 0)
    _ = try recipient.open(ciphertext: ciphertext.span, authenticatedData: bytes("616164").span)
    XCTAssertEqual(recipient.sequenceNumber, 1)
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

  private func bytes(repeating value: UInt8, count: Int) -> ContiguousArray<UInt8> {
    ContiguousArray(repeating: value, count: count)
  }

  private func copy(_ span: Span<UInt8>) -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }
}
