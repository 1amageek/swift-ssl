public enum TLS13HandshakeCoreEffect: ~Copyable, Sendable {
    case action(TLS13HandshakeCoreAction)
    case trafficSecrets(epoch: TLS13HandshakeEpoch, secrets: TLS13TrafficSecretPair)
}
