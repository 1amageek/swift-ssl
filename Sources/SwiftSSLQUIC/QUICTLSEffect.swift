public enum QUICTLSEffect: ~Copyable, Sendable {
    case action(QUICTLSAction)
    case trafficSecret(QUICTrafficSecretEvent)
}
