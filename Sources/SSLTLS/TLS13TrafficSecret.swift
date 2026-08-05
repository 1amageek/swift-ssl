import SSLCore
import SSLCrypto

/// One owned TLS 1.3 application traffic secret associated with its endpoint.
public struct TLS13TrafficSecret: ~Copyable, Sendable {
    public let endpoint: TLSRole
    public let cipherSuite: TLSCipherSuite
    private let owner: TLSTrafficSecret

    package init(
        endpoint: TLSRole,
        cipherSuite: TLSCipherSuite,
        secret: consuming SecretBytes
    ) {
        self.endpoint = endpoint
        self.cipherSuite = cipherSuite
        self.owner = TLSTrafficSecret(
            endpoint: endpoint,
            algorithmIdentifier: cipherSuite.rawValue,
            secret: consume secret
        )
    }

    public borrowing func withBorrowedSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try owner.withBorrowedSecret(body)
    }

    package consuming func takeSecret() -> SecretBytes {
        owner.takeSecret()
    }
}
import TLSTypes
