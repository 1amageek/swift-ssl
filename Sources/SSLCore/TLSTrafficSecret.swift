import TLSTypes

/// The owning boundary for one TLS-family traffic secret.
///
/// `SSLCore` owns the secret bytes and their wipe contract. Protocol layers
/// retain only metadata and borrow the bytes for one synchronous operation.
public struct TLSTrafficSecret: ~Copyable, Sendable {
    public let endpoint: TLSRole
    public let algorithmIdentifier: UInt16
    private let secret: SecretBytes

    public init(
        endpoint: TLSRole,
        algorithmIdentifier: UInt16,
        secret: consuming SecretBytes
    ) {
        self.endpoint = endpoint
        self.algorithmIdentifier = algorithmIdentifier
        self.secret = consume secret
    }

    public borrowing func withBorrowedSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try secret.withBorrowedBytes(body)
    }

    public consuming func takeSecret() -> SecretBytes {
        secret
    }
}
