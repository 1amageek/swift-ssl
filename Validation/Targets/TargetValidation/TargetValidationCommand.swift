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
  }

  static func main() throws {
    try validateAESGCM()
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
