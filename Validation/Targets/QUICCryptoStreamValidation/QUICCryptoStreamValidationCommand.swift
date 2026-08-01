import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLQUIC
import SwiftSSLTLS

@main
enum QUICCryptoStreamValidationCommand {
  enum Failure: Error {
    case incorrectBytes
    case incorrectOverlapFailure
    case missingEffect
    case secretMismatch
    case handshakeDidNotComplete
  }

  static func main() throws {
    var stream = try QUICTLSHandshakeStream.make(
      encryptionLevel: .handshake,
      maximumBufferedByteCount: 8,
      maximumMessageByteCount: 8
    )
    let first: ContiguousArray<UInt8> = [1, 0, 0, 1, 0xAA]
    try stream.receive(offset: 0, bytes: first.span)
    guard try stream.withNextMessage({ copy($0) }) == first else {
      throw Failure.incorrectBytes
    }
    try stream.discardNextMessage()

    let tail: ContiguousArray<UInt8> = [0xBB, 0xCC]
    let head: ContiguousArray<UInt8> = [2, 0, 0, 2]
    try stream.receive(offset: 9, bytes: tail.span)
    try stream.receive(offset: 5, bytes: head.span)
    guard try stream.withNextMessage({ copy($0) }) == [2, 0, 0, 2, 0xBB, 0xCC] else {
      throw Failure.incorrectBytes
    }

    let conflict: ContiguousArray<UInt8> = [1]
    do {
      try stream.receive(offset: 7, bytes: conflict.span)
      throw Failure.incorrectOverlapFailure
    } catch let error as QUICTLSHandshakeStreamError {
      guard error == .reassembly(.conflictingOverlap(offset: 7)) else {
        throw Failure.incorrectOverlapFailure
      }
    }

    try validateFullHandshake()

    print("swift-ssl QUIC TLS handshake validation: ok")
  }

  private struct StepSnapshot {
    var initialBytes: OwnedBytes?
    var handshakeBytes: OwnedBytes?
    var oneRTTBytes: OwnedBytes?
    var readHandshake: ContiguousArray<UInt8>?
    var writeHandshake: ContiguousArray<UInt8>?
    var readOneRTT: ContiguousArray<UInt8>?
    var writeOneRTT: ContiguousArray<UInt8>?
    var completed = false
    var confirmed = false

    mutating func store(
      _ bytes: OwnedBytes,
      at level: QUICHandshakeEncryptionLevel
    ) {
      switch level {
      case .initial: initialBytes = bytes
      case .handshake: handshakeBytes = bytes
      case .oneRTT: oneRTTBytes = bytes
      }
    }

    mutating func store(
      _ bytes: ContiguousArray<UInt8>,
      direction: QUICSecretDirection,
      level: QUICTrafficSecretLevel
    ) {
      switch (direction, level) {
      case (.read, .handshake): readHandshake = bytes
      case (.write, .handshake): writeHandshake = bytes
      case (.read, .oneRTT): readOneRTT = bytes
      case (.write, .oneRTT): writeOneRTT = bytes
      case (.read, .zeroRTT), (.write, .zeroRTT): break
      }
    }

    func secret(
      _ direction: QUICSecretDirection,
      _ level: QUICTrafficSecretLevel
    ) -> ContiguousArray<UInt8>? {
      switch (direction, level) {
      case (.read, .handshake): readHandshake
      case (.write, .handshake): writeHandshake
      case (.read, .oneRTT): readOneRTT
      case (.write, .oneRTT): writeOneRTT
      case (.read, .zeroRTT), (.write, .zeroRTT): nil
      }
    }
  }

  private struct Endpoints: ~Copyable {
    var client: QUICTLSClientHandshake
    var server: QUICTLSServerHandshake
  }

  private static func validateFullHandshake() throws {
    var endpoints = try makeEndpoints()
    let start = try snapshot(endpoints.client.start())
    guard let clientHello = start.initialBytes else {
      throw Failure.missingEffect
    }
    let split = clientHello.count / 2
    try endpoints.server.receiveCrypto(
      level: .initial,
      offset: UInt64(split),
      bytes: clientHello.span.extracting(split..<clientHello.count)
    )
    let incomplete = try endpoints.server.processNextMessage(at: .initial)
    switch consume incomplete {
    case .none: break
    case .some: throw Failure.handshakeDidNotComplete
    }
    try endpoints.server.receiveCrypto(
      level: .initial,
      offset: 0,
      bytes: clientHello.span.extracting(0..<split)
    )
    guard let serverStep = try endpoints.server.processNextMessage(at: .initial) else {
      throw Failure.missingEffect
    }
    let server = try snapshot(serverStep)
    guard let serverHello = server.initialBytes,
          let serverFlight = server.handshakeBytes else {
      throw Failure.missingEffect
    }
    try endpoints.client.receiveCrypto(
      level: .initial,
      offset: 0,
      bytes: serverHello.span
    )
    guard let helloStep = try endpoints.client.processNextMessage(at: .initial) else {
      throw Failure.missingEffect
    }
    let clientHelloResult = try snapshot(helloStep)
    guard clientHelloResult.secret(.read, .handshake)
            == server.secret(.write, .handshake),
          clientHelloResult.secret(.write, .handshake)
            == server.secret(.read, .handshake) else {
      throw Failure.secretMismatch
    }
    try endpoints.client.receiveCrypto(
      level: .handshake,
      offset: 0,
      bytes: serverFlight.span
    )
    var clientFinished: OwnedBytes?
    var clientRead: ContiguousArray<UInt8>?
    var clientWrite: ContiguousArray<UInt8>?
    var clientCompleted = false
    while let step = try endpoints.client.processNextMessage(at: .handshake) {
      let current = try snapshot(step)
      if let bytes = current.handshakeBytes { clientFinished = bytes }
      if let secret = current.secret(.read, .oneRTT) { clientRead = secret }
      if let secret = current.secret(.write, .oneRTT) { clientWrite = secret }
      clientCompleted = clientCompleted || current.completed
    }
    guard let clientFinished,
          clientCompleted,
          clientRead == server.secret(.write, .oneRTT),
          clientWrite == server.secret(.read, .oneRTT) else {
      throw Failure.secretMismatch
    }
    try endpoints.server.receiveCrypto(
      level: .handshake,
      offset: 0,
      bytes: clientFinished.span
    )
    guard let confirmationStep = try endpoints.server.processNextMessage(at: .handshake) else {
      throw Failure.missingEffect
    }
    let confirmation = try snapshot(confirmationStep)
    guard endpoints.client.isEstablished,
          endpoints.server.isEstablished,
          confirmation.completed,
          confirmation.confirmed else {
      throw Failure.handshakeDidNotComplete
    }
  }

  private static func snapshot(
    _ output: consuming QUICTLSStepOutput
  ) throws -> StepSnapshot {
    var output = consume output
    var result = StepSnapshot()
    while let effect = try output.nextEffect() {
      switch consume effect {
      case .action(.emitHandshakeBytes(let level, let range)):
        let bytes = try output.withBorrowedBytes { owner throws(ByteError) in
          guard range.endOffset <= owner.count else {
            throw .outOfBounds(
              offset: range.offset,
              requested: range.count,
              available: Swift.max(0, owner.count - range.offset)
            )
          }
          return OwnedBytes(
            copying: owner.extracting(range.offset..<range.endOffset)
          )
        }
        result.store(bytes, at: level)
      case .action(.handshakeComplete): result.completed = true
      case .action(.handshakeConfirmed): result.confirmed = true
      case .action(.sendAlert): throw Failure.handshakeDidNotComplete
      case .trafficSecret(let event):
        result.store(
          event.withBorrowedSecret { copy($0) },
          direction: event.direction,
          level: event.level
        )
      }
    }
    return result
  }

  private static func makeEndpoints() throws -> Endpoints {
    let instant = try VerificationInstant(
      secondsSinceUnixEpoch: 1_720_000_000,
      nanoseconds: 0
    )
    let clientKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x11, count: 32).span
    )
    let serverKey = try X25519PrivateKey(
      bytes: ContiguousArray(repeating: 0x22, count: 32).span
    )
    let signingKey = try Ed25519PrivateKey(seed: deterministicSeed().span)
    let client = try QUICTLSClientHandshake.make(
      random: ContiguousArray(repeating: 0x01, count: 32).span,
      ephemeralKey: clientKey,
      expectedServerPublicKey: deterministicServerPublicKey().span,
      verificationInstant: instant
    )
    let server = try QUICTLSServerHandshake.make(
      random: ContiguousArray(repeating: 0x02, count: 32).span,
      ephemeralKey: serverKey,
      certificateDER: deterministicCertificate().span,
      signingKey: .ed25519(signingKey),
      verificationInstant: instant
    )
    return Endpoints(client: client, server: server)
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

  private static func deterministicSeed() -> ContiguousArray<UInt8> {
    [
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
      0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ]
  }

  private static func deterministicServerPublicKey() -> ContiguousArray<UInt8> {
    [
      0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
      0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
      0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ]
  }

  private static func deterministicCertificate() -> ContiguousArray<UInt8> {
    [
      0x30, 0x81, 0xa6, 0x30, 0x5a, 0x02, 0x01, 0x01,
      0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30,
      0x00, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30,
      0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31,
      0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7,
      0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5,
      0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e,
      0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf,
      0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a, 0x30,
      0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41,
      0x00, 0x37, 0xdf, 0xbf, 0x24, 0xeb, 0x69, 0x2e,
      0x0b, 0xe9, 0x24, 0x3a, 0x10, 0xe9, 0x0e, 0x7a,
      0x42, 0x05, 0x28, 0xf6, 0xdc, 0xd6, 0x03, 0x28,
      0x98, 0xdc, 0xa9, 0x56, 0xd5, 0x1c, 0xe3, 0xa2,
      0x86, 0xb1, 0x55, 0x96, 0x38, 0x08, 0x32, 0xa6,
      0x0c, 0xc5, 0x7d, 0x2a, 0x84, 0xf8, 0x43, 0xc7,
      0x74, 0xff, 0xe0, 0xa7, 0xb4, 0x62, 0xa9, 0x55,
      0x6f, 0x76, 0x75, 0x1a, 0x87, 0x0d, 0x5c, 0x79,
      0x01,
    ]
  }
}
