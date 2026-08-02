import SwiftSSLCore

/// Stable immutable ownership for the prepared AES-GCM state used by HPKE.
///
/// The reference is private to one noncopyable HPKE context. Its stable address
/// prevents the expanded inline key schedule from being bulk-moved as setup
/// values cross construction boundaries. Concurrent reads are safe because
/// AES-GCM message operations do not mutate the prepared state.
final class HPKEAESGCMOwner: Sendable {
  private let cipher: AESGCM

  init(key: Span<UInt8>) throws(AEADError) {
    cipher = try AESGCM(key: key)
  }

  func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    try cipher.seal(
      plaintext: plaintext,
      authenticatedData: authenticatedData,
      nonce: nonce,
      into: &output
    )
  }

  func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(AEADError) {
    try cipher.open(
      ciphertextAndTag: ciphertext,
      authenticatedData: authenticatedData,
      nonce: nonce,
      into: &output
    )
  }
}
