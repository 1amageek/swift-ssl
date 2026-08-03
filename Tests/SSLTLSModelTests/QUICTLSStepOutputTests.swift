import SSLCore
import SSLCrypto
import SSLQUIC
import XCTest

final class QUICTLSStepOutputTests: XCTestCase {
  func testDeliversActionsAndSecretsInDeclaredOrderExactlyOnce() throws {
    let source: ContiguousArray<UInt8> = [10, 20, 30]
    let bytes = OwnedBytes(copying: source.span)
    let range = try ByteRange(offset: 1, count: 2)
    let actions: ContiguousArray<QUICTLSAction> = [
      .emitHandshakeBytes(level: .handshake, bytes: range),
      .handshakeComplete,
    ]
    let batch = try QUICTLSActionBatch(bytes: bytes, actions: actions)
    let readSecret = try makeSecretEvent(
      direction: .read,
      level: .handshake,
      bytes: (1, 2, 3, 4)
    )
    let writeSecret = try makeSecretEvent(
      direction: .write,
      level: .oneRTT,
      bytes: (5, 6, 7, 8)
    )
    var slots = QUICTrafficSecretSlots()
    try slots.insert(readSecret)
    try slots.insert(writeSecret)
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .trafficSecret(direction: .read, level: .handshake),
      .action(index: 0),
      .trafficSecret(direction: .write, level: .oneRTT),
      .action(index: 1),
    ]
    var output = try QUICTLSStepOutput(
      batch: batch,
      order: order,
      secrets: slots
    )

    let borrowedByteSum = output.withBorrowedBytes { bytes in
      bytes[0] + bytes[1] + bytes[2]
    }
    XCTAssertEqual(borrowedByteSum, 60)
    XCTAssertEqual(output.remainingEffectCount, 4)

    guard let first = try output.nextEffect() else {
      XCTFail("Expected the read handshake secret")
      return
    }
    switch consume first {
    case .trafficSecret(let event):
      XCTAssertEqual(event.direction, .read)
      XCTAssertEqual(event.level, .handshake)
      XCTAssertEqual(event.cipherSuite, .aes128GCM_SHA256)
      let sum = event.withBorrowedSecret { secret in
        secret[0] + secret[1] + secret[2] + secret[3]
      }
      XCTAssertEqual(sum, 10)
    case .action:
      XCTFail("Expected a traffic secret")
    }
    XCTAssertEqual(output.remainingEffectCount, 3)

    guard let second = try output.nextEffect() else {
      XCTFail("Expected the first action")
      return
    }
    switch consume second {
    case .action(let action):
      XCTAssertEqual(
        action,
        .emitHandshakeBytes(level: .handshake, bytes: range)
      )
    case .trafficSecret:
      XCTFail("Expected an action")
    }

    guard let third = try output.nextEffect() else {
      XCTFail("Expected the write 1-RTT secret")
      return
    }
    switch consume third {
    case .trafficSecret(let event):
      XCTAssertEqual(event.direction, .write)
      XCTAssertEqual(event.level, .oneRTT)
      let sum = event.withBorrowedSecret { secret in
        secret[0] + secret[1] + secret[2] + secret[3]
      }
      XCTAssertEqual(sum, 26)
    case .action:
      XCTFail("Expected a traffic secret")
    }

    guard let fourth = try output.nextEffect() else {
      XCTFail("Expected the second action")
      return
    }
    switch consume fourth {
    case .action(let action):
      XCTAssertEqual(action, .handshakeComplete)
    case .trafficSecret:
      XCTFail("Expected an action")
    }

    XCTAssertEqual(output.remainingEffectCount, 0)
    let exhausted = try output.nextEffect()
    switch consume exhausted {
    case .none:
      break
    case .some:
      XCTFail("Each effect must be delivered exactly once")
    }
  }

  func testRejectsOutOfBoundsActionIndex() throws {
    let batch = try makeBatch(actions: [.handshakeComplete])
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .action(index: 1)
    ]

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: QUICTrafficSecretSlots()
      )
      _ = output.remainingEffectCount
      XCTFail("Expected an out-of-bounds action error")
    } catch {
      XCTAssertEqual(
        error,
        .actionIndexOutOfBounds(index: 1, actionCount: 1)
      )
    }
  }

  func testRejectsDuplicateAction() throws {
    let batch = try makeBatch(actions: [.handshakeComplete])
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .action(index: 0),
      .action(index: 0),
    ]

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: QUICTrafficSecretSlots()
      )
      _ = output.remainingEffectCount
      XCTFail("Expected a duplicate action error")
    } catch {
      XCTAssertEqual(error, .duplicateAction(index: 0))
    }
  }

  func testRejectsUnreferencedAction() throws {
    let batch = try makeBatch(
      actions: [.handshakeComplete, .handshakeConfirmed]
    )
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .action(index: 0)
    ]

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: QUICTrafficSecretSlots()
      )
      _ = output.remainingEffectCount
      XCTFail("Expected an unreferenced action error")
    } catch {
      XCTAssertEqual(error, .unreferencedAction(index: 1))
    }
  }

  func testRejectsMissingTrafficSecretStorage() throws {
    let batch = try makeBatch(actions: [])
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .trafficSecret(direction: .read, level: .handshake)
    ]

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: QUICTrafficSecretSlots()
      )
      _ = output.remainingEffectCount
      XCTFail("Expected a missing secret storage error")
    } catch {
      XCTAssertEqual(
        error,
        .missingTrafficSecretStorage(
          direction: .read,
          level: .handshake
        )
      )
    }
  }

  func testRejectsUnreferencedTrafficSecret() throws {
    let batch = try makeBatch(actions: [])
    let secret = try makeSecretEvent(
      direction: .read,
      level: .handshake,
      bytes: (1, 2, 3, 4)
    )
    var slots = QUICTrafficSecretSlots()
    try slots.insert(secret)
    let order: ContiguousArray<QUICTLSEffectDescriptor> = []

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: slots
      )
      _ = output.remainingEffectCount
      XCTFail("Expected an unreferenced traffic secret error")
    } catch {
      XCTAssertEqual(
        error,
        .unreferencedTrafficSecret(
          direction: .read,
          level: .handshake
        )
      )
    }
  }

  func testRejectsDuplicateTrafficSecretDescriptor() throws {
    let batch = try makeBatch(actions: [])
    let secret = try makeSecretEvent(
      direction: .write,
      level: .oneRTT,
      bytes: (1, 2, 3, 4)
    )
    var slots = QUICTrafficSecretSlots()
    try slots.insert(secret)
    let order: ContiguousArray<QUICTLSEffectDescriptor> = [
      .trafficSecret(direction: .write, level: .oneRTT),
      .trafficSecret(direction: .write, level: .oneRTT),
    ]

    do {
      let output = try QUICTLSStepOutput(
        batch: batch,
        order: order,
        secrets: slots
      )
      _ = output.remainingEffectCount
      XCTFail("Expected a duplicate traffic secret error")
    } catch {
      XCTAssertEqual(
        error,
        .duplicateTrafficSecret(
          direction: .write,
          level: .oneRTT
        )
      )
    }
  }

  func testSecretStorageSelectsAllSlotsFromEventMetadata() throws {
    let coordinates:
      ContiguousArray<
        (
          QUICSecretDirection,
          QUICTrafficSecretLevel
        )
      > = [
        (.read, .zeroRTT),
        (.write, .zeroRTT),
        (.read, .handshake),
        (.write, .handshake),
        (.read, .oneRTT),
        (.write, .oneRTT),
      ]
    var slots = QUICTrafficSecretSlots()
    var order = ContiguousArray<QUICTLSEffectDescriptor>()
    order.reserveCapacity(coordinates.count)

    var coordinateIndex = 0
    while coordinateIndex < coordinates.count {
      let coordinate = coordinates[coordinateIndex]
      let marker = UInt8(coordinateIndex + 1)
      let event = try makeSecretEvent(
        direction: coordinate.0,
        level: coordinate.1,
        bytes: (marker, 0, 0, 0)
      )
      try slots.insert(event)
      order.append(
        .trafficSecret(
          direction: coordinate.0,
          level: coordinate.1
        )
      )
      coordinateIndex += 1
    }

    var output = try QUICTLSStepOutput(
      batch: makeBatch(actions: []),
      order: order,
      secrets: slots
    )

    coordinateIndex = 0
    while coordinateIndex < coordinates.count {
      guard let effect = try output.nextEffect() else {
        XCTFail("Expected a traffic secret for every coordinate")
        return
      }
      let expected = coordinates[coordinateIndex]
      switch consume effect {
      case .action:
        XCTFail("Expected a traffic secret")
      case .trafficSecret(let event):
        XCTAssertEqual(event.direction, expected.0)
        XCTAssertEqual(event.level, expected.1)
        let marker = event.withBorrowedSecret { secret in secret[0] }
        XCTAssertEqual(marker, UInt8(coordinateIndex + 1))
      }
      coordinateIndex += 1
    }
  }

  func testRejectsDuplicateTrafficSecretStorage() throws {
    var slots = QUICTrafficSecretSlots()
    let first = try makeSecretEvent(
      direction: .read,
      level: .handshake,
      bytes: (1, 2, 3, 4)
    )
    try slots.insert(first)
    let duplicate = try makeSecretEvent(
      direction: .read,
      level: .handshake,
      bytes: (5, 6, 7, 8)
    )

    do {
      try slots.insert(duplicate)
      XCTFail("Expected duplicate secret storage to fail")
    } catch {
      XCTAssertEqual(
        error,
        .duplicateTrafficSecretStorage(
          direction: .read,
          level: .handshake
        )
      )
    }
  }

  private func makeBatch(
    actions: consuming ContiguousArray<QUICTLSAction>
  ) throws -> QUICTLSActionBatch {
    let source: ContiguousArray<UInt8> = []
    return try QUICTLSActionBatch(
      bytes: OwnedBytes(copying: source.span),
      actions: actions
    )
  }

  private func makeSecretEvent(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel,
    bytes: (UInt8, UInt8, UInt8, UInt8)
  ) throws -> QUICTrafficSecretEvent {
    let byteCount = try SecretByteCount(4)
    let secret = SecretBytes(byteCount: byteCount) { destination in
      destination[0] = bytes.0
      destination[1] = bytes.1
      destination[2] = bytes.2
      destination[3] = bytes.3
    }
    return QUICTrafficSecretEvent(
      direction: direction,
      level: level,
      cipherSuite: .aes128GCM_SHA256,
      secret: secret
    )
  }
}
