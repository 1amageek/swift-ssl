import SwiftSSLCrypto

/// AES-GCM with caller-owned input and output spans.
public struct AESGCM: ~Copyable, AuthenticatedCipher {
  public static let supportedKeyByteCounts =
    SwiftSSLCrypto.AESGCM.supportedKeyByteCounts
  public static let nonceByteCount = SwiftSSLCrypto.AESGCM.nonceByteCount
  public static let tagByteCount = SwiftSSLCrypto.AESGCM.tagByteCount

  private var implementation: SwiftSSLCrypto.AESGCM

  public init(key: Span<UInt8>) throws(AEADError) {
    do {
      implementation = try SwiftSSLCrypto.AESGCM(key: key)
    } catch {
      throw AEADError(error)
    }
  }

  public mutating func seal(
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

  public mutating func open(
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
