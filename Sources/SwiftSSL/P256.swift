import SwiftSSLCore
import SwiftSSLCrypto

/// Deterministic RFC 6979 P-256 ECDSA exposed by the SwiftSSL façade.
public enum P256ECDSA: DigestDigitalSignature {
  public typealias PrivateKey = P256PrivateKey
  public typealias PublicKey = P256PublicKey

  public static let signatureByteCount = SwiftSSLCrypto.P256ECDSA.signatureByteCount

  public static func sign(
    messageHash: Span<UInt8>,
    using privateKey: borrowing P256PrivateKey
  ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
    do {
      return try SwiftSSLCrypto.P256ECDSA.sign(
        messageHash: messageHash,
        using: privateKey.implementation
      )
    } catch {
      throw CryptoInputError(error)
    }
  }

  public static func verify(
    signature: Span<UInt8>,
    messageHash: Span<UInt8>,
    using publicKey: borrowing P256PublicKey
  ) throws(CryptoInputError) -> Bool {
    do {
      return try SwiftSSLCrypto.P256ECDSA.verify(
        signature: signature,
        messageHash: messageHash,
        using: publicKey.implementation
      )
    } catch {
      throw CryptoInputError(error)
    }
  }
}
