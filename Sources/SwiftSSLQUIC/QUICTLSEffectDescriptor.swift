public enum QUICTLSEffectDescriptor: Sendable, Hashable {
    case action(index: Int)
    case trafficSecret(
        direction: QUICSecretDirection,
        level: QUICTrafficSecretLevel
    )
}
