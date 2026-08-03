import SSLCore
import SSLCrypto

public struct QUICTrafficSecretEvent: ~Copyable, Sendable {
    public let direction: QUICSecretDirection
    public let level: QUICTrafficSecretLevel
    public let cipherSuite: TLSCipherSuite
    private let secret: SecretBytes

    package init(
        direction: QUICSecretDirection,
        level: QUICTrafficSecretLevel,
        cipherSuite: TLSCipherSuite,
        secret: consuming SecretBytes
    ) {
        self.direction = direction
        self.level = level
        self.cipherSuite = cipherSuite
        self.secret = secret
    }

    public borrowing func withBorrowedSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try secret.withBorrowedBytes(body)
    }
}
