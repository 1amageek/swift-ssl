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

  public borrowing func makeApplicationSecrets(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> TLS13ApplicationSecrets {
    try TLS13ApplicationSecrets(
      cipherSuite: cipherSuite,
      masterSecret: masterSecret,
      transcriptHash: transcriptHash
    )
  }

  /// Derives the resumption master secret only after Client Finished has
  /// been incorporated into the transcript, as required by RFC 8446.
  public borrowing func makeResumptionMasterSecret(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> TLS13ResumptionMasterSecret {
    let secret = try TLS13KeySchedule.deriveSecret(
      secret: masterSecret,
      label: "res master",
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
    return TLS13ResumptionMasterSecret(
      cipherSuite: cipherSuite,
      secret: secret
    )
  }

  public borrowing func makeClientFinishedVerifyData(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    try TLS13KeySchedule.finishedVerifyData(
      trafficSecret: clientTrafficSecret,
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
  }

  public borrowing func makeServerFinishedVerifyData(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    try TLS13KeySchedule.finishedVerifyData(
      trafficSecret: serverTrafficSecret,
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
  }

}
