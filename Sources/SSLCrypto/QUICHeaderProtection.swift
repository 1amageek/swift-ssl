import SSLCore

/// RFC 9001 §5.4 header-protection masks.
///
/// The returned mask is exactly five bytes. The block/stream primitive remains
/// private to `SSLCrypto`; callers receive only the protocol-level result.
public enum QUICHeaderProtection {
  public static func aes(
    key: Span<UInt8>,
    sample: Span<UInt8>
  ) throws(AEADError) -> ContiguousArray<UInt8> {
    let block = try DTLSRecordNumberMask.aes(key: key, sample: sample)
    return ContiguousArray(block.prefix(5))
  }

  public static func chaCha20(
    key: Span<UInt8>,
    sample: Span<UInt8>
  ) throws(AEADError) -> ContiguousArray<UInt8> {
    let block = try DTLSRecordNumberMask.chaCha20(key: key, sample: sample)
    return ContiguousArray(block.prefix(5))
  }
}
