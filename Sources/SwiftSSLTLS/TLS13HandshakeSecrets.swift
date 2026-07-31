import SwiftSSLCore
import SwiftSSLCrypto

public struct TLS13HandshakeSecrets: ~Copyable, Sendable {
    public let cipherSuite: TLSCipherSuite

    private let clientTrafficSecret: SecretBytes
    private let serverTrafficSecret: SecretBytes
    private let masterSecret: SecretBytes

    init(
        cipherSuite: TLSCipherSuite,
        clientTrafficSecret: consuming SecretBytes,
        serverTrafficSecret: consuming SecretBytes,
        masterSecret: consuming SecretBytes
    ) {
        self.cipherSuite = cipherSuite
        self.clientTrafficSecret = clientTrafficSecret
        self.serverTrafficSecret = serverTrafficSecret
        self.masterSecret = masterSecret
    }

    public borrowing func withClientTrafficSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientTrafficSecret.withBorrowedBytes(body)
    }

    public borrowing func withServerTrafficSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverTrafficSecret.withBorrowedBytes(body)
    }

    public consuming func makeApplicationSecrets(
        transcriptHash: Span<UInt8>
    ) throws(TLS13KeyScheduleError) -> TLS13ApplicationSecrets {
        try TLS13ApplicationSecrets(
            cipherSuite: cipherSuite,
            masterSecret: masterSecret,
            transcriptHash: transcriptHash
        )
    }
}
