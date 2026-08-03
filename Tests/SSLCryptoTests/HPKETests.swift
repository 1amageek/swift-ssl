import SSLCore
import XCTest

@testable import SSLCrypto

final class HPKETests: XCTestCase {
  func testP256AllModesRoundTrip() throws {
    let recipient = P256KeyPair(
      privateKey: try P256PrivateKey(bytes: bytes(repeating: 0x11, count: 32).span)
    )
    let sender = P256KeyPair(
      privateKey: try P256PrivateKey(bytes: bytes(repeating: 0x22, count: 32).span)
    )
    let info = bytes("503235362d48504b45")
    let psk = bytes("503235362d70736b")
    let pskID = bytes("503235362d70736b2d6964")
    let plaintext = bytes("503235362d7061796c6f6164")
    let aad = bytes("503235362d616164")

    var baseSetup = try HPKEP256.setupBaseSender(
      recipientPublicKey: recipient.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305,
      using: FixedEntropy(bytes: bytes(repeating: 0x31, count: 32))
    )
    var baseRecipient = try HPKEP256.setupBaseRecipient(
      encapsulation: baseSetup.encapsulation.span,
      recipientKeyPair: recipient,
      info: info.span,
      kdf: .sha256,
      aead: .chaCha20Poly1305
    )
    var baseSender = baseSetup.takeContext()
    try assertRoundTrip(
      sender: &baseSender,
      recipient: &baseRecipient,
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )

    var pskSetup = try HPKEP256.setupPSKSender(
      recipientPublicKey: recipient.publicKey,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha384,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x32, count: 32))
    )
    var pskRecipient = try HPKEP256.setupPSKRecipient(
      encapsulation: pskSetup.encapsulation.span,
      recipientKeyPair: recipient,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha384,
      aead: .aes128GCM
    )
    var pskSender = pskSetup.takeContext()
    try assertRoundTrip(
      sender: &pskSender,
      recipient: &pskRecipient,
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )

    var authSetup = try HPKEP256.setupAuthSender(
      recipientPublicKey: recipient.publicKey,
      senderKeyPair: sender,
      info: info.span,
      kdf: .sha512,
      aead: .aes256GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x33, count: 32))
    )
    var authRecipient = try HPKEP256.setupAuthRecipient(
      encapsulation: authSetup.encapsulation.span,
      recipientKeyPair: recipient,
      senderPublicKey: sender.publicKey,
      info: info.span,
      kdf: .sha512,
      aead: .aes256GCM
    )
    var authSender = authSetup.takeContext()
    try assertRoundTrip(
      sender: &authSender,
      recipient: &authRecipient,
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )

    var authPSKSetup = try HPKEP256.setupAuthPSKSender(
      recipientPublicKey: recipient.publicKey,
      senderKeyPair: sender,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x34, count: 32))
    )
    var authPSKRecipient = try HPKEP256.setupAuthPSKRecipient(
      encapsulation: authPSKSetup.encapsulation.span,
      recipientKeyPair: recipient,
      senderPublicKey: sender.publicKey,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var authPSKSender = authPSKSetup.takeContext()
    try assertRoundTrip(
      sender: &authPSKSender,
      recipient: &authPSKRecipient,
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
  }

  func testP256EncodedBaseSenderMatchesPreparedPathAndRejectsInvalidKey() throws {
    let recipient = P256KeyPair(
      privateKey: try P256PrivateKey(bytes: bytes(repeating: 0x41, count: 32).span)
    )
    let info = bytes("503235362d656e636f6465642d73656e646572")
    let plaintext = bytes("7061796c6f6164")
    let authenticatedData = bytes("616164")
    let entropy = bytes(repeating: 0x53, count: 32)

    var preparedSetup = try HPKEP256.setupBaseSender(
      recipientPublicKey: recipient.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: entropy)
    )
    var encodedSetup = try HPKEP256.setupBaseSender(
      recipientPublicKeyBytes: recipient.publicKey.span,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: entropy)
    )
    XCTAssertEqual(
      copy(preparedSetup.encapsulation.span),
      copy(encodedSetup.encapsulation.span)
    )

    var preparedSender = preparedSetup.takeContext()
    var encodedSender = encodedSetup.takeContext()
    let preparedCiphertext = try preparedSender.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span
    )
    let encodedCiphertext = try encodedSender.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span
    )
    XCTAssertEqual(copy(preparedCiphertext.span), copy(encodedCiphertext.span))

    let invalidKey = bytes(repeating: 0, count: P256PublicKey.uncompressedByteCount)
    do {
      _ = try HPKEP256.setupBaseSender(
        recipientPublicKeyBytes: invalidKey.span,
        info: info.span,
        kdf: .sha256,
        aead: .aes128GCM,
        using: FixedEntropy(bytes: entropy)
      )
      XCTFail("invalid encoded P-256 recipient key was accepted")
    } catch {
      XCTAssertEqual(error, .primitive(.invalidPeerKey))
    }
  }

  func testP256RejectsInvalidEncapsulation() throws {
    let recipient = P256KeyPair(
      privateKey: try P256PrivateKey(bytes: bytes(repeating: 0x41, count: 32).span)
    )
    let invalidEncapsulation = bytes(repeating: 0, count: P256PublicKey.uncompressedByteCount)

    do {
      _ = try HPKEP256.setupBaseRecipient(
        encapsulation: invalidEncapsulation.span,
        recipientKeyPair: recipient,
        info: ContiguousArray<UInt8>().span,
        kdf: .sha256,
        aead: .aes128GCM
      )
      XCTFail("invalid P-256 encapsulation was accepted")
    } catch {
      XCTAssertEqual(error, .invalidEncapsulation)
    }
  }

  func testRFC9180P256AES128BaseVector() throws {
    let recipient = P256KeyPair(
      privateKey: try P256PrivateKey(
        bytes: bytes(
          "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"
        ).span
      )
    )
    let entropy = FixedEntropy(
      bytes: bytes(
        "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
      )
    )
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    var setup = try HPKEP256.setupBaseSender(
      recipientPublicKey: recipient.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: entropy
    )
    XCTAssertEqual(
      copy(setup.encapsulation.span),
      Array(
        bytes(
          "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac"
            + "98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
        )
      )
    )
    var recipientContext = try HPKEP256.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientKeyPair: recipient,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var senderContext = setup.takeContext()
    let plaintext = bytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad = bytes("436f756e742d30")
    let ciphertext = try senderContext.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(
      copy(ciphertext.span),
      Array(
        bytes(
          "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f"
            + "9076ac232e3ab2523f39513434"
        )
      )
    )
    let opened = try recipientContext.open(
      ciphertext: ciphertext.span,
      authenticatedData: aad.span
    )
    XCTAssertEqual(copy(opened.span), Array(plaintext))
    let exported = try senderContext.export(ContiguousArray<UInt8>().span, length: 32)
    XCTAssertEqual(
      exported.withBorrowedBytes { copy($0) },
      Array(bytes("5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d"))
    )
  }

  private func assertRoundTrip(
    sender: inout HPKESenderContext,
    recipient: inout HPKERecipientContext,
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>
  ) throws {
    let ciphertext = try sender.seal(
      plaintext: plaintext,
      authenticatedData: authenticatedData
    )
    let opened = try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: authenticatedData
    )
    XCTAssertEqual(copy(opened.span), copy(plaintext))
    let senderExport = try sender.export(bytes("01").span, length: 32)
    let recipientExport = try recipient.export(bytes("01").span, length: 32)
    XCTAssertEqual(
      senderExport.withBorrowedBytes { copy($0) },
      recipientExport.withBorrowedBytes { copy($0) }
    )
    XCTAssertEqual(sender.sequenceNumber, 1)
    XCTAssertEqual(recipient.sequenceNumber, 1)
  }

  func testRFC9180X25519ChaChaBaseVector() throws {
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"
        ).span))
    let entropy = FixedEntropy(
      bytes: bytes(
        "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"
      ))
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    var setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey,
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
      recipientKeyPair: recipientPrivate,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82"
        ).span))
    let senderPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05"
        ).span))
    let entropy = FixedEntropy(
      bytes: bytes(
        "c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13"
      ))
    let info = bytes("4f6465206f6e2061204772656369616e2055726e")
    var setup = try HPKEX25519.setupAuthSender(
      recipientPublicKey: recipientPrivate.publicKey,
      senderKeyPair: senderPrivate,
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
      recipientKeyPair: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879"
        ).span))
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
      recipientPublicKey: recipientPrivate.publicKey,
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
      recipientKeyPair: recipientPrivate,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c"
        ).span))
    let senderPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(
          "90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418"
        ).span))
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
      recipientPublicKey: recipientPrivate.publicKey,
      senderKeyPair: senderPrivate,
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
      recipientKeyPair: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: bytes(repeating: 0x11, count: 32).span))
    let info = bytes("00112233445566778899aabbccddeeff")
    let plaintext = bytes("706c61696e74657874")
    let aad = bytes("616164")
    let kdFs: [HPKEKDF] = [.sha256, .sha384, .sha512]
    let aeads: [HPKEAEAD] = [.aes128GCM, .aes256GCM, .chaCha20Poly1305]

    for kdf in kdFs {
      for aead in aeads {
        let entropy = FixedEntropy(bytes: bytes(repeating: 0x22, count: 32))
        var setup = try HPKEX25519.setupBaseSender(
          recipientPublicKey: recipientPrivate.publicKey,
          info: info.span,
          kdf: kdf,
          aead: aead,
          using: entropy
        )
        var recipient = try HPKEX25519.setupBaseRecipient(
          encapsulation: setup.encapsulation.span,
          recipientKeyPair: recipientPrivate,
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
        let secondPlaintext = bytes("73657175656e63652d6f6e65")
        let secondAAD = bytes("6161642d6f6e65")
        let secondCiphertext = try sender.seal(
          plaintext: secondPlaintext.span,
          authenticatedData: secondAAD.span
        )
        let secondOpened = try recipient.open(
          ciphertext: secondCiphertext.span,
          authenticatedData: secondAAD.span
        )
        XCTAssertEqual(copy(secondOpened.span), Array(secondPlaintext))
        let senderExport = try sender.export(bytes("01").span, length: 32)
        let recipientExport = try recipient.export(bytes("01").span, length: 32)
        let senderExportBytes = senderExport.withBorrowedBytes { copy($0) }
        let recipientExportBytes = recipientExport.withBorrowedBytes { copy($0) }
        XCTAssertEqual(senderExportBytes, recipientExportBytes)
        XCTAssertEqual(sender.sequenceNumber, 2)
        XCTAssertEqual(recipient.sequenceNumber, 2)
      }
    }
  }

  func testPSKRoundTripAndIdentityValidation() throws {
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: bytes(repeating: 0x31, count: 32).span))
    let psk = bytes("000102030405060708090a0b0c0d0e0f")
    let pskID = bytes("746573742d70736b")
    let info = bytes("696e666f")
    let entropy = FixedEntropy(bytes: bytes(repeating: 0x32, count: 32))
    var setup = try HPKEX25519.setupPSKSender(
      recipientPublicKey: recipientPrivate.publicKey,
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
      recipientKeyPair: recipientPrivate,
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
        recipientKeyPair: recipientPrivate,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: bytes(repeating: 0x41, count: 32).span))
    let senderPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: bytes(repeating: 0x42, count: 32).span))
    let info = bytes("61757468")
    let psk = bytes("50534b2d736563726574")
    let pskID = bytes("70736b2d6964")
    let aad = bytes("616164")
    let plaintext = bytes("617574682d7061796c6f6164")

    var authSetup = try HPKEX25519.setupAuthSender(
      recipientPublicKey: recipientPrivate.publicKey,
      senderKeyPair: senderPrivate,
      info: info.span,
      kdf: .sha384,
      aead: .aes256GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x43, count: 32))
    )
    var authRecipient = try HPKEX25519.setupAuthRecipient(
      encapsulation: authSetup.encapsulation.span,
      recipientKeyPair: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey,
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
      recipientPublicKey: recipientPrivate.publicKey,
      senderKeyPair: senderPrivate,
      info: info.span,
      psk: psk.span,
      pskID: pskID.span,
      kdf: .sha512,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x44, count: 32))
    )
    var authPSKRecipient = try HPKEX25519.setupAuthPSKRecipient(
      encapsulation: authPSKSetup.encapsulation.span,
      recipientKeyPair: recipientPrivate,
      senderPublicKey: senderPrivate.publicKey,
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
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(bytes: bytes(repeating: 0x51, count: 32).span))
    var setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey,
      info: bytes("69").span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x52, count: 32))
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientKeyPair: recipientPrivate,
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

  func testInPlaceSealAndOpenMatchAllocatingAPI() throws {
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(repeating: 0x61, count: 32).span
      ))
    let info = bytes("696e2d706c616365")
    let aad = bytes("616164")
    let plaintext = bytes("7061796c6f61642d776974686f75742d636f7079")
    let entropyBytes = bytes(repeating: 0x62, count: 32)
    var allocatingSetup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: entropyBytes)
    )
    var allocatingSender = allocatingSetup.takeContext()
    let expected = try allocatingSender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )

    var inPlaceSetup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: entropyBytes)
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: inPlaceSetup.encapsulation.span,
      recipientKeyPair: recipientPrivate,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var inPlaceSender = inPlaceSetup.takeContext()
    var ciphertext = ContiguousArray<UInt8>(
      repeating: 0xA5,
      count: plaintext.count + HPKEAEAD.tagByteCount
    )
    var ciphertextSpan = ciphertext.mutableSpan
    try inPlaceSender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span,
      into: &ciphertextSpan
    )
    XCTAssertEqual(Array(ciphertext), copy(expected.span))
    XCTAssertEqual(inPlaceSender.sequenceNumber, 1)

    var opened = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    var openedSpan = opened.mutableSpan
    try recipient.open(
      ciphertext: ciphertext.span,
      authenticatedData: aad.span,
      into: &openedSpan
    )
    XCTAssertEqual(opened, plaintext)
    XCTAssertEqual(recipient.sequenceNumber, 1)
  }

  func testInPlaceFailuresPreserveDestinationAndSequence() throws {
    let recipientPrivate = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(repeating: 0x71, count: 32).span
      ))
    let info = bytes("69")
    let aad = bytes("616164")
    let plaintext = bytes("706c61696e")
    var setup = try HPKEX25519.setupBaseSender(
      recipientPublicKey: recipientPrivate.publicKey,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM,
      using: FixedEntropy(bytes: bytes(repeating: 0x72, count: 32))
    )
    var recipient = try HPKEX25519.setupBaseRecipient(
      encapsulation: setup.encapsulation.span,
      recipientKeyPair: recipientPrivate,
      info: info.span,
      kdf: .sha256,
      aead: .aes128GCM
    )
    var sender = setup.takeContext()
    var wrongSized = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    let wrongSizedOriginal = wrongSized
    do {
      var destination = wrongSized.mutableSpan
      try sender.seal(
        plaintext: plaintext.span,
        authenticatedData: aad.span,
        into: &destination
      )
      XCTFail("an undersized HPKE destination was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .authenticatedCipher(
          .outputTooSmall(
            required: plaintext.count + HPKEAEAD.tagByteCount,
            actual: plaintext.count
          )
        )
      )
    }
    XCTAssertEqual(wrongSized, wrongSizedOriginal)
    XCTAssertEqual(sender.sequenceNumber, 0)

    let validCiphertext = try sender.seal(
      plaintext: plaintext.span,
      authenticatedData: aad.span
    )
    var corrupted = ContiguousArray(copy(validCiphertext.span))
    corrupted[corrupted.count - 1] ^= 0x01
    var opened = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    let openedOriginal = opened
    do {
      var destination = opened.mutableSpan
      try recipient.open(
        ciphertext: corrupted.span,
        authenticatedData: aad.span,
        into: &destination
      )
      XCTFail("an invalid HPKE tag was accepted")
    } catch {
      XCTAssertEqual(error, .authenticatedCipher(.authenticationFailed))
    }
    XCTAssertEqual(opened, openedOriginal)
    XCTAssertEqual(recipient.sequenceNumber, 0)
  }

  func testSenderSetupPreservesEntropyFailureType() throws {
    let recipient = X25519KeyPair(
      privateKey: try X25519PrivateKey(
        bytes: bytes(repeating: 0x81, count: 32).span
      ))
    do {
      _ = try HPKEX25519.setupBaseSender(
        recipientPublicKey: recipient.publicKey,
        info: ContiguousArray<UInt8>().span,
        kdf: .sha256,
        aead: .aes128GCM,
        using: FailingEntropy()
      )
      XCTFail("an entropy failure was accepted")
    } catch {
      XCTAssertEqual(
        error,
        .keyGeneration(.entropy(.unavailable))
      )
    }
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
      throw .unavailable
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
