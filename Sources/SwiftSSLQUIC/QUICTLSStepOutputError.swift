public enum QUICTLSStepOutputError: Error, Sendable, Equatable {
  case actionIndexOutOfBounds(index: Int, actionCount: Int)
  case duplicateAction(index: Int)
  case unreferencedAction(index: Int)
  case duplicateTrafficSecret(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  )
  case duplicateTrafficSecretStorage(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  )
  case missingTrafficSecretStorage(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  )
  case unreferencedTrafficSecret(
    direction: QUICSecretDirection,
    level: QUICTrafficSecretLevel
  )
}
