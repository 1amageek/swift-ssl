
public protocol AuthenticatedCipher: ~Copyable, Sendable {
  static var supportedKeyByteCounts: [Int] { get }
  static var nonceByteCount: Int { get }
  static var tagByteCount: Int { get }

  /// Inputs and output may use one exact starting address for in-place GCTR.
  /// Authenticated data must not overlap output. Partial overlaps are typed
  /// failures and are rejected before output mutation.

  func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError)

  func open(
    ciphertextAndTag: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError)
}
