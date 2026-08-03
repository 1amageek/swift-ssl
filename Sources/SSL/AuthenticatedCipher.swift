public protocol AuthenticatedCipher: ~Copyable, Sendable {
  static var supportedKeyByteCounts: [Int] { get }
  static var nonceByteCount: Int { get }
  static var tagByteCount: Int { get }

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
