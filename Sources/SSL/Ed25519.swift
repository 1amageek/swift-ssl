import SSLCore
import SSLCrypto

public enum Ed25519 {
  public static let publicKeyByteCount = SSLCrypto.Ed25519.publicKeyByteCount
  public static let signatureByteCount = SSLCrypto.Ed25519.signatureByteCount

  public static func verify(
    signature: Span<UInt8>,
    message: Span<UInt8>,
    using publicKey: borrowing Ed25519PublicKey
  ) throws(CryptoInputError) -> Bool {
    do {
      return try SSLCrypto.Ed25519.verify(
        signature: signature,
        message: message,
        using: publicKey.implementation
      )
    } catch {
      throw CryptoInputError(error)
    }
  }
}
