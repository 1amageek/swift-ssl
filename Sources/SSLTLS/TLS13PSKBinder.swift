import SSLCore
import SSLCrypto

public struct TLS13PSKBinder: Sendable, Hashable {
  public static let minimumByteCount = 32
  public static let maximumByteCount = 255

  public let value: OwnedBytes

  public init(value: Span<UInt8>) throws(TLS13PSKError) {
    guard value.count >= Self.minimumByteCount,
      value.count <= Self.maximumByteCount
    else {
      throw .invalidBinderLength(value.count)
    }
    self.value = OwnedBytes(copying: value)
  }

  /// Computes the binder over an RFC 8446 truncated-ClientHello transcript
  /// hash prepared by the handshake engine.
  public static func compute(
    preSharedKey: borrowing SecretBytes,
    cipherSuite: TLSCipherSuite,
    transcriptHash: Span<UInt8>
  ) throws(TLS13PSKError) -> OwnedBytes {
    do {
      let binderKey = try TLS13KeySchedule.deriveResumptionBinderKey(
        preSharedKey: preSharedKey,
        cipherSuite: cipherSuite
      )
      return try TLS13KeySchedule.finishedVerifyData(
        trafficSecret: binderKey,
        transcriptHash: transcriptHash,
        cipherSuite: cipherSuite
      )
    } catch {
      throw .derivationFailed
    }
  }

  public static func verify(
    preSharedKey: borrowing SecretBytes,
    cipherSuite: TLSCipherSuite,
    transcriptHash: Span<UInt8>,
    binder: Span<UInt8>
  ) throws(TLS13PSKError) -> Bool {
    let expected = try compute(
      preSharedKey: preSharedKey,
      cipherSuite: cipherSuite,
      transcriptHash: transcriptHash
    )
    guard binder.count == expected.count else { return false }
    return ConstantTime.equal(binder, expected.span)
  }
}
