import SSLCore

public struct TLS13ServerKeyExchangeResult: ~Copyable, Sendable {
    public let serverShare: OwnedBytes
    public let sharedSecret: SecretBytes

    public init(
        serverShare: consuming OwnedBytes,
        sharedSecret: consuming SecretBytes
    ) {
        self.serverShare = serverShare
        self.sharedSecret = sharedSecret
    }
}
