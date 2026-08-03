import SSLCrypto

/// AES-GCM with caller-owned input and output spans.
public struct AESGCM: ~Copyable, AuthenticatedCipher, Sendable {
  public static let supportedKeyByteCounts =
    SSLCrypto.AESGCM.supportedKeyByteCounts
  public static let nonceByteCount = SSLCrypto.AESGCM.nonceByteCount
  public static let tagByteCount = SSLCrypto.AESGCM.tagByteCount

  private let implementation: SSLCrypto.AESGCM

  public init(key: Span<UInt8>) throws(AEADError) {
    do {
      implementation = try SSLCrypto.AESGCM(key: key)
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
