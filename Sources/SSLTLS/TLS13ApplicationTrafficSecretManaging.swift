public protocol TLS13ApplicationTrafficSecretManaging: ~Copyable, Sendable {
    mutating func updateApplicationTrafficSecret(
        for endpoint: TLSRole
    ) throws(TLS13HandshakeEngineError) -> TLS13TrafficSecret
}
import SSLTypes
