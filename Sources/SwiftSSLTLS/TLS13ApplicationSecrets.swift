import SwiftSSLCore
import SwiftSSLCrypto

public struct TLS13ApplicationSecrets: ~Copyable, Sendable {
    public let cipherSuite: TLSCipherSuite

    private let clientTrafficSecret: SecretBytes
    private let serverTrafficSecret: SecretBytes
    private let exporterMasterSecret: SecretBytes
    private let resumptionMasterSecret: SecretBytes

    init(
        cipherSuite: TLSCipherSuite,
        masterSecret: borrowing SecretBytes,
        transcriptHash: Span<UInt8>
    ) throws(TLS13KeyScheduleError) {
        let hashByteCount = TLS13KeySchedule.hashByteCount(for: cipherSuite)
        guard transcriptHash.count == hashByteCount else {
            throw .invalidTranscriptHashLength(expected: hashByteCount, actual: transcriptHash.count)
        }
        let client = try TLS13KeySchedule.deriveSecret(
            secret: masterSecret,
            label: "c ap traffic",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        let server = try TLS13KeySchedule.deriveSecret(
            secret: masterSecret,
            label: "s ap traffic",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        let exporter = try TLS13KeySchedule.deriveSecret(
            secret: masterSecret,
            label: "exp master",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        let resumption = try TLS13KeySchedule.deriveSecret(
            secret: masterSecret,
            label: "res master",
            transcriptHash: transcriptHash,
            cipherSuite: cipherSuite
        )
        self.cipherSuite = cipherSuite
        clientTrafficSecret = client
        serverTrafficSecret = server
        exporterMasterSecret = exporter
        resumptionMasterSecret = resumption
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

    public borrowing func withExporterMasterSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try exporterMasterSecret.withBorrowedBytes(body)
    }

    public borrowing func withResumptionMasterSecret<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try resumptionMasterSecret.withBorrowedBytes(body)
    }
}
