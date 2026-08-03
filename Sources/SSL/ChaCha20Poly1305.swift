import SSLCrypto

/// RFC 8439 ChaCha20-Poly1305 with caller-owned input and output spans.
public struct ChaCha20Poly1305: ~Copyable, AuthenticatedCipher, Sendable {
  public static let supportedKeyByteCounts =
    SSLCrypto.ChaCha20Poly1305.supportedKeyByteCounts
  public static let nonceByteCount = SSLCrypto.ChaCha20Poly1305.nonceByteCount
  public static let tagByteCount = SSLCrypto.ChaCha20Poly1305.tagByteCount

  private let implementation: SSLCrypto.ChaCha20Poly1305

  public init(key: Span<UInt8>) throws(AEADError) {
    do {
      implementation = try SSLCrypto.ChaCha20Poly1305(key: key)
    } catch {
      throw AEADError(error)
    }
  }

  public func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    do {
      try implementation.seal(
        plaintext: plaintext,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &output
      )
    } catch {
      throw AEADError(error)
    }
  }

  public func open(
    ciphertextAndTag: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    do {
      try implementation.open(
        ciphertextAndTag: ciphertextAndTag,
        authenticatedData: authenticatedData,
        nonce: nonce,
        into: &output
      )
    } catch {
      throw AEADError(error)
    }
  }
}
