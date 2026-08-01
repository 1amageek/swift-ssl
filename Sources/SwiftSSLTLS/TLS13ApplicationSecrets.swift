import SwiftSSLCore
import SwiftSSLCrypto

public struct TLS13ApplicationSecrets: ~Copyable, Sendable {
    public let cipherSuite: TLSCipherSuite

    private var clientTrafficSecret: SecretBytes
    private var serverTrafficSecret: SecretBytes
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

    public borrowing func withClientTrafficSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try clientTrafficSecret.withBorrowedBytes(body)
    }

    public borrowing func withServerTrafficSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try serverTrafficSecret.withBorrowedBytes(body)
    }

    package borrowing func exportTrafficSecrets()
        throws(SecretMemoryError) -> TLS13TrafficSecretPair
    {
        let client = try clientTrafficSecret.withBorrowedBytes { bytes throws(SecretMemoryError) in
            try SecretBytes(copying: bytes)
        }
        let server = try serverTrafficSecret.withBorrowedBytes { bytes throws(SecretMemoryError) in
            try SecretBytes(copying: bytes)
        }
        return TLS13TrafficSecretPair(
            cipherSuite: cipherSuite,
            clientSecret: consume client,
            serverSecret: consume server
        )
    }

    public borrowing func withExporterMasterSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try exporterMasterSecret.withBorrowedBytes(body)
    }

    public borrowing func withResumptionMasterSecret<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try resumptionMasterSecret.withBorrowedBytes(body)
    }

    public mutating func updateClientTrafficSecret() throws(TLS13KeyScheduleError) {
        let next = try TLS13KeySchedule.updateTrafficSecret(
            secret: clientTrafficSecret,
            cipherSuite: cipherSuite
        )
        clientTrafficSecret = consume next
    }

    public mutating func updateServerTrafficSecret() throws(TLS13KeyScheduleError) {
        let next = try TLS13KeySchedule.updateTrafficSecret(
            secret: serverTrafficSecret,
            cipherSuite: cipherSuite
        )
        serverTrafficSecret = consume next
    }
}
