import SSLCore

public protocol KeyEncapsulationMechanism: Sendable {
  associatedtype PublicKey: Sendable
  associatedtype PrivateKey: ~Copyable & Sendable
  associatedtype Encapsulation: Sendable
  associatedtype SharedSecret: ~Copyable & Sendable

  static func generateKeyPair(
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey>

  static func encapsulate(
    to publicKey: borrowing PublicKey,
    using entropy: borrowing any EntropySource
  ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret>

  /// Correctly structured ML-KEM ciphertexts use implicit rejection and
  /// therefore return a shared secret instead of revealing validity.
  static func decapsulate(
    _ encapsulation: borrowing Encapsulation,
    using privateKey: borrowing PrivateKey
  ) throws(KEMError) -> SharedSecret
}
