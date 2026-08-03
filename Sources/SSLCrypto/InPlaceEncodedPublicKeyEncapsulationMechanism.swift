import SSLCore

/// A KEM that can validate and consume a borrowed encoded public key directly.
public protocol InPlaceEncodedPublicKeyEncapsulationMechanism:
  InPlaceKeyEncapsulationMechanism
{
  static var publicKeyByteCount: Int { get }

  static func encapsulate(
    toEncodedPublicKey publicKey: Span<UInt8>,
    using entropy: borrowing any EntropySource,
    into encapsulation: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError)
}
