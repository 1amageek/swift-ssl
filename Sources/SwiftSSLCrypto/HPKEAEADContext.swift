import SwiftSSLCore

/// A prepared message-protection context owned by one HPKE sender or recipient.
///
/// The selected cipher expands its key exactly once during HPKE setup. Message
/// operations borrow the immutable key schedule while the outer HPKE context
/// exclusively owns nonce sequence progression.
enum HPKEAEADContext: ~Copyable, Sendable {
  case aesGCM(HPKEAESGCMOwner)
  case chaCha20Poly1305(ChaCha20Poly1305)

  init(key: Span<UInt8>, algorithm: HPKEAEAD) throws(HPKEError) {
    do {
      switch algorithm {
      case .aes128GCM, .aes256GCM:
        self = .aesGCM(try HPKEAESGCMOwner(key: key))
      case .chaCha20Poly1305:
        self = .chaCha20Poly1305(try ChaCha20Poly1305(key: key))
      }
    } catch let error {
      throw .authenticatedCipher(error)
    }
  }

  borrowing func seal(
    plaintext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    do {
      switch self {
      case .aesGCM(let owner):
        try owner.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      case .chaCha20Poly1305(let cipher):
        try cipher.seal(
          plaintext: plaintext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      }
    } catch let error {
      throw .authenticatedCipher(error)
    }
  }

  borrowing func open(
    ciphertext: Span<UInt8>,
    authenticatedData: Span<UInt8>,
    nonce: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(HPKEError) {
    do {
      switch self {
      case .aesGCM(let owner):
        try owner.open(
          ciphertext: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      case .chaCha20Poly1305(let cipher):
        try cipher.open(
          ciphertextAndTag: ciphertext,
          authenticatedData: authenticatedData,
          nonce: nonce,
          into: &output
        )
      }
    } catch let error {
      throw .authenticatedCipher(error)
    }
  }
}
