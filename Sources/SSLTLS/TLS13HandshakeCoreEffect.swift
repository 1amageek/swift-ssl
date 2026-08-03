public enum TLS13HandshakeCoreEffect: ~Copyable, Sendable {
    case action(TLS13HandshakeCoreAction)
    case earlyTrafficSecret(
        TLS13EarlyTrafficSecret,
        disposition: TLS13EarlyTrafficSecretDisposition
    )
    case trafficSecrets(epoch: TLS13HandshakeEpoch, secrets: TLS13TrafficSecretPair)
}
