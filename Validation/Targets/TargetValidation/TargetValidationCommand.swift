import SwiftSSL
import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLQUIC
import SwiftSSLTLS

@main
enum TargetValidationCommand {
  enum Failure: Error {
    case aesGCM
    case chacha20Poly1305
    case x25519
    case hmacDRBG
    case sha384512
    case sha3
    case byteCursor
    case derCursor
    case secretOwner
    case sha256
    case hmacSHA256
    case hkdfSHA256
    case actionBatch
    case quicSecret
    case quicStepOutput
    case profileBoundary
    case uint24Failure
    case dtlsReplay
    case quicInitial
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

  static func main() throws {
    try validateAESGCM()
    try validateChaCha20Poly1305()
    try validateX25519()
    try validateHMACDRBG()
    try validateSHA384AndSHA512()
    try validateSHA3()
    try validateSHA256()
    try validateHMACSHA256()
    try validateHKDFSHA256()
    try validateActionBatch()
    try validateByteCursor()
    try validateDERCursor()
    try validateProfiles()
    try validateQUICSecretEvent()
    try validateQUICStepOutput()
    try validateSecretOwner()
    try validateUInt24Failure()
    try validateDTLSReplay()
    try validateQUICInitial()
    print("swift-ssl target validation: ok")
  }

  private static func validateAESGCM() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 16)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>(repeating: 0, count: 16)
    let authenticatedData = ContiguousArray<UInt8>()
    let expected: ContiguousArray<UInt8> = [
      0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
      0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
      0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
      0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    var cipher = try SwiftSSL.AESGCM(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: authenticatedData.span,
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else {
      throw Failure.aesGCM
    }

    var recovered = ContiguousArray<UInt8>(repeating: 0xA5, count: plaintext.count)
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: authenticatedData.span,
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else {
      throw Failure.aesGCM
    }
  }

  private static func validateDTLSReplay() throws {
    var window = DTLS13ReplayWindow()
    guard try window.accept(10) == .accepted,
      try window.accept(9) == .accepted,
      try window.accept(10) == .replayed
    else {
      throw Failure.dtlsReplay
    }
  }

  private static func validateQUICInitial() throws {
    let connectionID = ContiguousArray<UInt8>([
      0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ])
    let secrets = try QUICInitialSecrets(destinationConnectionID: connectionID.span)
    let expected = ContiguousArray<UInt8>([
      0x1F, 0x36, 0x96, 0x13, 0xDD, 0x76, 0xD5, 0x46,
      0x77, 0x30, 0xEF, 0xCB, 0xE3, 0xB1, 0xA2, 0x2D,
    ])
    guard secrets.withClientKey({ key in copy(key) }) == expected else {
      throw Failure.quicInitial
    }
  }

  private static func copy(_ span: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(span.count)
    var index = 0
    while index < span.count {
      result.append(span[index])
      index += 1
    }
    return result
  }

  private static func validateChaCha20Poly1305() throws {
    let key = ContiguousArray<UInt8>(repeating: 0, count: 32)
    let nonce = ContiguousArray<UInt8>(repeating: 0, count: 12)
    let plaintext = ContiguousArray<UInt8>()
    let expected: ContiguousArray<UInt8> = [
      0x4E, 0xB9, 0x72, 0xC9, 0xA8, 0xFB, 0x3A, 0x1B,
      0x38, 0x2B, 0xB4, 0xD3, 0x6F, 0x5F, 0xFA, 0xD1,
    ]
    var sealed = ContiguousArray<UInt8>(repeating: 0, count: expected.count)
    var cipher = try SwiftSSL.ChaCha20Poly1305(key: key.span)
    var sealedSpan = sealed.mutableSpan
    try cipher.seal(
      plaintext: plaintext.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &sealedSpan
    )
    guard sealed == expected else { throw Failure.chacha20Poly1305 }

    var recovered = ContiguousArray<UInt8>()
    var recoveredSpan = recovered.mutableSpan
    try cipher.open(
      ciphertextAndTag: sealed.span,
      authenticatedData: plaintext.span,
      nonce: nonce.span,
      into: &recoveredSpan
    )
    guard recovered == plaintext else { throw Failure.chacha20Poly1305 }
  }

  private static func validateX25519() throws {
    let alicePrivate = ContiguousArray<UInt8>([
      0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
      0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
      0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
      0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A,
    ])
    let bobPrivate = ContiguousArray<UInt8>(0..<32)
    let expectedPublic = ContiguousArray<UInt8>([
      0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54,
      0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
      0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4,
      0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
    ])
    let expectedShared = ContiguousArray<UInt8>([
      0x5B, 0xF2, 0x20, 0xD6, 0x70, 0xC9, 0x4B, 0x8D,
      0x70, 0xBC, 0x5E, 0xDE, 0x1C, 0xFF, 0xB8, 0x5D,
      0x6C, 0x4B, 0x7C, 0x9D, 0x87, 0x17, 0xBB, 0xB5,
      0xEB, 0x90, 0xC0, 0x25, 0x83, 0x86, 0x20, 0x07,
    ])
    let alice = try SwiftSSL.X25519PrivateKey(bytes: alicePrivate.span)
    let bob = try SwiftSSL.X25519PrivateKey(bytes: bobPrivate.span)
    let publicKey = alice.publicKey()
    guard publicKey.span.count == expectedPublic.count else {
      throw Failure.x25519
    }
    var index = 0
    while index < expectedPublic.count {
      guard publicKey.span[index] == expectedPublic[index] else {
        throw Failure.x25519
      }
      index += 1
    }
    let shared = try SwiftSSL.X25519.sharedSecret(
      privateKey: alice,
      peerPublicKey: bob.publicKey()
    )
    let matches = shared.withBorrowedBytes { bytes in
      guard bytes.count == expectedShared.count else { return false }
      var index = 0
      while index < bytes.count {
        if bytes[index] != expectedShared[index] { return false }
        index += 1
      }
      return true
    }
    guard matches else { throw Failure.x25519 }
  }

  private static func validateHMACDRBG() throws {
    let entropy = FixedEntropy(bytes: ContiguousArray(0..<32))
    let nonce = ContiguousArray<UInt8>(32..<48)
    let personalization = ContiguousArray<UInt8>(48..<64)
    var generator = try HMACDRBG(
      entropy: entropy,
      nonce: nonce.span,
      personalization: personalization.span
    )
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var outputSpan = output.mutableSpan
    try generator.generate(into: &outputSpan)
    let expected = ContiguousArray<UInt8>([
      0xAC, 0xB4, 0xC0, 0x52, 0x73, 0x46, 0x34, 0x3F,
      0x45, 0x26, 0x6A, 0x99, 0xA5, 0xEA, 0x86, 0xE9,
      0x49, 0x3B, 0x69, 0x63, 0x5F, 0x50, 0x9E, 0xD6,
      0x87, 0x1D, 0x4C, 0x87, 0x1F, 0x93, 0x61, 0x3B,
    ])
    guard output == expected else { throw Failure.hmacDRBG }
  }

  private static func validateSHA384AndSHA512() throws {
    let input = ContiguousArray("abc".utf8)
    let expected384 = ContiguousArray<UInt8>([
      0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
    ])
    let expected512 = ContiguousArray<UInt8>([
      0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F,
    ])
    var output384 = ContiguousArray<UInt8>(repeating: 0, count: SwiftSSL.SHA384.digestByteCount)
    var output384Span = output384.mutableSpan
    try SwiftSSL.SHA384.hash(input.span, into: &output384Span)
    var output512 = ContiguousArray<UInt8>(repeating: 0, count: SwiftSSL.SHA512.digestByteCount)
    var output512Span = output512.mutableSpan
    try SwiftSSL.SHA512.hash(input.span, into: &output512Span)
    guard output384 == expected384, output512 == expected512 else { throw Failure.sha384512 }
  }

  private static func validateSHA3() throws {
    var sha3 = ContiguousArray<UInt8>(repeating: 0, count: SwiftSSLCrypto.SHA3_256.digestByteCount)
    var sha3Span = sha3.mutableSpan
    try SwiftSSLCrypto.SHA3_256.hash(ContiguousArray<UInt8>().span, into: &sha3Span)
    let expected = ContiguousArray<UInt8>([
      0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
      0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
      0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA,
      0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A,
    ])
    guard sha3 == expected else { throw Failure.sha3 }

    var shake = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var shakeSpan = shake.mutableSpan
    try SwiftSSLCrypto.SHAKE128.hash(
      ContiguousArray<UInt8>().span,
      outputByteCount: 32,
      into: &shakeSpan
    )
    let shakeExpected = ContiguousArray<UInt8>([
      0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D,
      0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3E,
      0xD7, 0x3B, 0x80, 0x93, 0xF6, 0xEF, 0xBC, 0x88,
      0xEB, 0x1A, 0x6E, 0xAC, 0xFA, 0x66, 0xEF, 0x26,
    ])
    guard shake == shakeExpected else { throw Failure.sha3 }
  }

  private static func validateSHA256() throws {
    let input: ContiguousArray<UInt8> = [0x61, 0x62, 0x63]
    let expected: ContiguousArray<UInt8> = [
      0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
      0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
      0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
      0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    ]
    var output = ContiguousArray<UInt8>(repeating: 0, count: 32)
    do {
      var outputSpan = output.mutableSpan
      try SwiftSSL.SHA256.hash(input.span, into: &outputSpan)
    }
    guard output == expected else {
      throw Failure.sha256
    }
  }

  private static func validateHMACSHA256() throws {
    let key = ContiguousArray<UInt8>(repeating: 0x0B, count: 20)
    let message = ContiguousArray("Hi There".utf8)
    let expected: ContiguousArray<UInt8> = [
      0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
      0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
      0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
      0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7,
    ]
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: SwiftSSL.HMACSHA256.tagByteCount
    )
    do {
      var outputSpan = output.mutableSpan
      try SwiftSSL.HMACSHA256.authenticate(
        message.span,
        using: key.span,
        into: &outputSpan
      )
    }
    guard output == expected,
      try SwiftSSL.HMACSHA256.isValidAuthenticationCode(
        expected.span,
        authenticating: message.span,
        using: key.span
      )
    else {
      throw Failure.hmacSHA256
    }
  }

  private static func validateHKDFSHA256() throws {
    let inputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0x0B,
      count: 22
    )
    let salt = ContiguousArray(UInt8(0x00)...UInt8(0x0C))
    let info = ContiguousArray(UInt8(0xF0)...UInt8(0xF9))
    let expectedPseudorandomKey: ContiguousArray<UInt8> = [
      0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
      0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
      0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
      0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5,
    ]
    let expectedOutputKeyMaterial: ContiguousArray<UInt8> = [
      0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
      0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
      0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
      0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF,
      0x34, 0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18,
      0x58, 0x65,
    ]

    var pseudorandomKey = ContiguousArray<UInt8>(
      repeating: 0,
      count: SwiftSSL.HKDFSHA256.pseudorandomKeyByteCount
    )
    do {
      var output = pseudorandomKey.mutableSpan
      try SwiftSSL.HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial.span,
        salt: salt.span,
        into: &output
      )
    }

    var outputKeyMaterial = ContiguousArray<UInt8>(
      repeating: 0,
      count: expectedOutputKeyMaterial.count
    )
    do {
      var output = outputKeyMaterial.mutableSpan
      try SwiftSSL.HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey.span,
        info: info.span,
        into: &output
      )
    }

    guard
      pseudorandomKey == expectedPseudorandomKey,
      outputKeyMaterial == expectedOutputKeyMaterial
    else {
      throw Failure.hkdfSHA256
    }
  }

  private static func validateUInt24Failure() throws {
    var builder = try ByteBuilder(maximumByteCount: 3)
    do {
      try builder.appendUInt24BigEndian(UInt32.max)
      throw Failure.uint24Failure
    } catch let error as ByteError {
      guard
        error
          == .integerDoesNotFit(
            value: UInt64(UInt32.max),
            byteCount: 3
          ), builder.count == 0
      else {
        throw Failure.uint24Failure
      }
    }
  }

  private static func validateByteCursor() throws {
    let input: ContiguousArray<UInt8> = [0x12, 0x34, 0x56]
    var cursor = ByteCursor(input.span)
    guard try cursor.readUInt16BigEndian() == 0x1234 else {
      throw Failure.byteCursor
    }
    guard try cursor.readByte() == 0x56 else {
      throw Failure.byteCursor
    }
    try cursor.requireFullyConsumed()
  }

  private static func validateQUICSecretEvent() throws {
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 1
      destination[1] = 2
      destination[2] = 3
      destination[3] = 4
    }
    let event = QUICTrafficSecretEvent(
      direction: .write,
      level: .handshake,
      cipherSuite: .aes128GCM_SHA256,
      secret: secret
    )
    let sum = event.withBorrowedSecret { bytes in
      bytes[0] + bytes[1] + bytes[2] + bytes[3]
    }
    guard sum == 10,
      event.direction == .write,
      event.level == .handshake,
      event.cipherSuite == .aes128GCM_SHA256
    else {
      throw Failure.quicSecret
    }
  }

  private static func validateQUICStepOutput() throws {
    let input: ContiguousArray<UInt8> = [1, 2, 3]
    let range = try ByteRange(offset: 0, count: 3)
    let actions: ContiguousArray<QUICTLSAction> = [
      .emitHandshakeBytes(level: .handshake, bytes: range),
      .handshakeComplete,
    ]
    let batch = try QUICTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: actions
    )
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 5
      destination[1] = 6
      destination[2] = 7
      destination[3] = 8
    }
    let event = QUICTrafficSecretEvent(
      direction: .write,
      level: .oneRTT,
      cipherSuite: .aes128GCM_SHA256,
      secret: secret
    )
    var slots = QUICTrafficSecretSlots()
    try slots.insert(event)
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .action(index: 0),
      .trafficSecret(direction: .write, level: .oneRTT),
      .action(index: 1),
    ]
    var output = try QUICTLSStepOutput(
      batch: batch,
      order: order,
      secrets: slots
    )

    guard let first = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume first {
    case .action(let action):
      guard
        action
          == .emitHandshakeBytes(
            level: .handshake,
            bytes: range
          )
      else {
        throw Failure.quicStepOutput
      }
    case .trafficSecret:
      throw Failure.quicStepOutput
    }

    guard let second = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume second {
    case .trafficSecret(let trafficSecret):
      let sum = trafficSecret.withBorrowedSecret { bytes in
        bytes[0] + bytes[1] + bytes[2] + bytes[3]
      }
      guard trafficSecret.direction == .write,
        trafficSecret.level == .oneRTT,
        sum == 26
      else {
        throw Failure.quicStepOutput
      }
    case .action:
      throw Failure.quicStepOutput
    }

    guard let third = try output.nextEffect() else {
      throw Failure.quicStepOutput
    }
    switch consume third {
    case .action(let action):
      guard action == .handshakeComplete else {
        throw Failure.quicStepOutput
      }
    case .trafficSecret:
      throw Failure.quicStepOutput
    }

    let exhausted = try output.nextEffect()
    switch consume exhausted {
    case .none:
      guard output.remainingEffectCount == 0 else {
        throw Failure.quicStepOutput
      }
    case .some:
      throw Failure.quicStepOutput
    }
  }

  private static func validateDERCursor() throws {
    let input: ContiguousArray<UInt8> = [0x02, 0x01, 0x05]
    let limits = try ParsingLimits(
      maximumInputBytes: 64,
      maximumNestingDepth: 4,
      maximumElementCount: 8,
      maximumExtensionCount: 4,
      maximumOIDBytes: 32,
      maximumStringBytes: 32
    )
    var budget = try ParsingBudget(limits: limits, inputByteCount: input.count)
    var cursor = DERCursor(input.span)
    let integer = try cursor.readElement(using: &budget)
    guard integer.tag.tagClass == .universal,
      integer.tag.number == 2,
      integer.contentBytes.count == 1,
      integer.contentBytes[0] == 5
    else {
      throw Failure.derCursor
    }
  }

  private static func validateSecretOwner() throws {
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = 1
      destination[1] = 2
      destination[2] = 3
      destination[3] = 4
    }
    let sum = secret.withBorrowedBytes { bytes in
      var result: UInt8 = 0
      var index = 0
      while index < bytes.count {
        result &+= bytes[index]
        index += 1
      }
      return result
    }
    guard sum == 10 else {
      throw Failure.secretOwner
    }
  }

  private static func validateActionBatch() throws {
    let input: ContiguousArray<UInt8> = [1, 2, 3]
    let range = try ByteRange(offset: 0, count: 3)
    var streamActions = ContiguousArray<TLSStreamAction>()
    streamActions.reserveCapacity(1)
    streamActions.append(.emitRecordBytes(range))
    let streamBatch = try TLSStreamActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: streamActions
    )

    var datagramActions = ContiguousArray<DTLSAction>()
    datagramActions.reserveCapacity(1)
    datagramActions.append(.emitDatagram(range))
    let datagramBatch = try DTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: datagramActions
    )

    var quicActions = ContiguousArray<QUICTLSAction>()
    quicActions.reserveCapacity(1)
    quicActions.append(.emitHandshakeBytes(level: .handshake, bytes: range))
    let quicBatch = try QUICTLSActionBatch(
      bytes: OwnedBytes(copying: input.span),
      actions: quicActions
    )

    guard streamBatch.actions.count == 1,
      datagramBatch.actions.count == 1,
      quicBatch.actions.count == 1,
      streamBatch.bytes.count == 3,
      datagramBatch.bytes.count == 3,
      quicBatch.bytes.count == 3
    else {
      throw Failure.actionBatch
    }
  }

  private static func validateProfiles() throws {
    guard TLSStream13Profile.usesTLSRecords,
      !DTLS13Profile.usesTLSRecords,
      DTLS13Profile.usesDatagramReliability,
      !QUICTLSProfile.usesTLSRecords
    else {
      throw Failure.profileBoundary
    }
  }
}
