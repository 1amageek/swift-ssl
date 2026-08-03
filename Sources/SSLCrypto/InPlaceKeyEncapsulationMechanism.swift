import SSLCore

public protocol InPlaceKeyEncapsulationMechanism: KeyEncapsulationMechanism {
  static var encapsulationByteCount: Int { get }
  static var sharedSecretByteCount: Int { get }

  static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError)

  /// Correctly sized ciphertexts use implicit rejection. The caller owns the
  /// secret output buffer and is responsible for erasing it after use.
  static func decapsulate(
    _ encapsulation: Span<UInt8>,
    using privateKey: borrowing PrivateKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError)
}
