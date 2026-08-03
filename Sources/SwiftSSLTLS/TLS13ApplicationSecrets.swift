import SwiftSSLCore
import SwiftSSLCrypto

public struct TLS13ApplicationSecrets: ~Copyable, Sendable {
  public let cipherSuite: TLSCipherSuite

  private var clientTrafficSecret: SecretBytes
  private var serverTrafficSecret: SecretBytes
  private let exporterMasterSecret: SecretBytes

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
    self.cipherSuite = cipherSuite
    clientTrafficSecret = client
    serverTrafficSecret = server
    exporterMasterSecret = exporter
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

  package borrowing func exportTrafficSecret(
    for endpoint: TLSRole
  ) throws(SecretMemoryError) -> TLS13TrafficSecret {
    switch endpoint {
    case .client:
      let copy = try clientTrafficSecret.withBorrowedBytes {
        bytes throws(SecretMemoryError) in
        try SecretBytes(copying: bytes)
      }
      return TLS13TrafficSecret(
        endpoint: endpoint,
        cipherSuite: cipherSuite,
        secret: copy
      )
    case .server:
      let copy = try serverTrafficSecret.withBorrowedBytes {
        bytes throws(SecretMemoryError) in
        try SecretBytes(copying: bytes)
      }
      return TLS13TrafficSecret(
        endpoint: endpoint,
        cipherSuite: cipherSuite,
        secret: copy
      )
    }
  }

  public borrowing func withExporterMasterSecret<Result: ~Copyable, Failure: Error>(
    _ body: (Span<UInt8>) throws(Failure) -> Result
  ) throws(Failure) -> Result {
    try exporterMasterSecret.withBorrowedBytes(body)
  }

  /// Implements the RFC 8446 exporter construction without materializing the
  /// exported secret in an intermediate public byte container.
  public borrowing func exportKeyingMaterial(
    label: String,
    context: Span<UInt8>,
    outputByteCount: Int
  ) throws(TLS13KeyScheduleError) -> SecretBytes {
    let emptyHash = try TLS13KeySchedule.hashEmptyMessage(
      cipherSuite: cipherSuite
    )
    let derived = try TLS13KeySchedule.deriveSecret(
      secret: exporterMasterSecret,
      label: label,
      transcriptHash: emptyHash.span,
      cipherSuite: cipherSuite
    )
    let contextHash = try Self.hash(
      context,
      cipherSuite: cipherSuite
    )
    return try TLS13KeySchedule.expandLabel(
      secret: derived,
      label: "exporter",
      context: contextHash.span,
      outputByteCount: outputByteCount,
      cipherSuite: cipherSuite
    )
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

  package borrowing func makeClientFinishedVerifyData(
    transcriptHash: Span<UInt8>
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    try TLS13KeySchedule.finishedVerifyData(
      trafficSecret: clientTrafficSecret,
      transcriptHash: transcriptHash,
      cipherSuite: cipherSuite
    )
  }

  private static func hash(
    _ input: Span<UInt8>,
    cipherSuite: TLSCipherSuite
  ) throws(TLS13KeyScheduleError) -> OwnedBytes {
    let outputByteCount = TLS13KeySchedule.hashByteCount(for: cipherSuite)
    var output = ContiguousArray<UInt8>(
      repeating: 0,
      count: outputByteCount
    )
    do {
      try output.withUnsafeMutableBufferPointer {
        buffer throws(CryptoInputError) in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: outputByteCount
        )
        switch cipherSuite {
        case .aes256GCM_SHA384:
          try SHA384.hash(input, into: &destination)
        case .aes128GCM_SHA256, .chacha20Poly1305_SHA256:
          try SHA256.hash(input, into: &destination)
        }
      }
    } catch {
      throw .cryptographicFailure
    }
    return OwnedBytes(consuming: output)
  }
}
