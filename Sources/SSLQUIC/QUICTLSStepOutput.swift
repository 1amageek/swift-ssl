import SSLCore

public struct QUICTLSStepOutput: ~Copyable, Sendable {
  private let batch: QUICTLSActionBatch
  private let order: ContiguousArray<QUICTLSEffectDescriptor>
  private var secrets: QUICTrafficSecretSlots
  private var nextEffectIndex: Int

  package init(
    batch: consuming QUICTLSActionBatch,
    order: consuming ContiguousArray<QUICTLSEffectDescriptor>,
    secrets: consuming QUICTrafficSecretSlots
  ) throws(QUICTLSStepOutputError) {
    try Self.validate(batch: batch, order: order, secrets: secrets)
    self.batch = batch
    self.order = order
    self.secrets = secrets
    nextEffectIndex = 0
  }

  public var remainingEffectCount: Int {
    order.count - nextEffectIndex
  }

  public borrowing func withBorrowedBytes<Result, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try body(batch.bytes.span)
  }

  public mutating func nextEffect()
    throws(QUICTLSStepOutputError) -> QUICTLSEffect?
  {
    guard nextEffectIndex < order.count else {
      return nil
    }

    let descriptor = order[nextEffectIndex]

    switch descriptor {
    case .action(let index):
      nextEffectIndex += 1
      return .action(batch.actions[index])
    case .trafficSecret(let direction, let level):
      guard let event = secrets.take(direction: direction, level: level) else {
        throw .missingTrafficSecretStorage(
          direction: direction,
          level: level
        )
      }
      nextEffectIndex += 1
      return .trafficSecret(event)
    }
  }

  private static func validate(
    batch: borrowing QUICTLSActionBatch,
    order: borrowing ContiguousArray<QUICTLSEffectDescriptor>,
    secrets: borrowing QUICTrafficSecretSlots
  ) throws(QUICTLSStepOutputError) {
    var descriptorIndex = 0
    while descriptorIndex < order.count {
      let descriptor = order[descriptorIndex]
      switch descriptor {
      case .action(let actionIndex):
        guard actionIndex >= 0, actionIndex < batch.actions.count else {
          throw .actionIndexOutOfBounds(
            index: actionIndex,
            actionCount: batch.actions.count
          )
        }
        guard
          !contains(
            .action(index: actionIndex),
            before: descriptorIndex,
            in: order
          )
        else {
          throw .duplicateAction(index: actionIndex)
        }
      case .trafficSecret(let direction, let level):
        guard secrets.contains(direction: direction, level: level) else {
          throw .missingTrafficSecretStorage(
            direction: direction,
            level: level
          )
        }
        guard
          !contains(
            .trafficSecret(direction: direction, level: level),
            before: descriptorIndex,
            in: order
          )
        else {
          throw .duplicateTrafficSecret(
            direction: direction,
            level: level
          )
        }
      }
      descriptorIndex += 1
    }

    var actionIndex = 0
    while actionIndex < batch.actions.count {
      guard order.contains(.action(index: actionIndex)) else {
        throw .unreferencedAction(index: actionIndex)
      }
      actionIndex += 1
    }

    try requireReferencedSecretSlots(order: order, secrets: secrets)
  }

  private static func contains(
    _ expected: QUICTLSEffectDescriptor,
    before endIndex: Int,
    in order: borrowing ContiguousArray<QUICTLSEffectDescriptor>
  ) -> Bool {
    var index = 0
    while index < endIndex {
      if order[index] == expected {
        return true
      }
      index += 1
    }
    return false
  }

  private static func requireReferencedSecretSlots(
    order: borrowing ContiguousArray<QUICTLSEffectDescriptor>,
    secrets: borrowing QUICTrafficSecretSlots
  ) throws(QUICTLSStepOutputError) {
    let directions: (QUICSecretDirection, QUICSecretDirection) = (
      .read,
      .write
    )
    let levels:
      (
        QUICTrafficSecretLevel,
        QUICTrafficSecretLevel,
        QUICTrafficSecretLevel
      ) = (.zeroRTT, .handshake, .oneRTT)

    try requireReferencedSecret(
      direction: directions.0,
      level: levels.0,
      order: order,
      secrets: secrets
    )
    try requireReferencedSecret(
      direction: directions.1,
      level: levels.0,
      order: order,
      secrets: secrets
    )
    try requireReferencedSecret(
      direction: directions.0,
      level: levels.1,
      order: order,
      secrets: secrets
    )
    try requireReferencedSecret(
      direction: directions.1,
      level: levels.1,
      order: order,
      secrets: secrets
    )
    try requireReferencedSecret(
      direction: directions.0,
      level: levels.2,
      order: order,
      secrets: secrets
    )
    try requireReferencedSecret(
      direction: directions.1,
      level: levels.2,
      order: order,
      secrets: secrets
    )
  }

  private static func requireReferencedSecret(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel,
    order: borrowing ContiguousArray<QUICTLSEffectDescriptor>,
    secrets: borrowing QUICTrafficSecretSlots
  ) throws(QUICTLSStepOutputError) {
    guard secrets.contains(direction: direction, level: level) else {
      return
    }
    guard
      order.contains(
        .trafficSecret(direction: direction, level: level)
      )
    else {
      throw .unreferencedTrafficSecret(
        direction: direction,
        level: level
      )
    }
  }
}
