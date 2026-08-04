// KeyAgreement.swift
// ECDH: X25519, P-256, P-384. Opaque key associatedtypes. Embedded-clean: no `any`.

/// A Diffie-Hellman key-agreement scheme (X25519, P-256, or P-384 ECDH).
///
/// Key material is modelled with `associatedtype`s so the scheme specialises
/// cleanly under Embedded Swift (no `any`). Concrete key types are defined by the
/// provider (M4).
public protocol KeyAgreement: Sendable {
    /// A private key for this scheme.
    associatedtype PrivateKey: Sendable

    /// A public key for this scheme.
    associatedtype PublicKey: Sendable

    /// Generates a fresh private key using the provider's secure RNG.
    static func generatePrivateKey() throws(CryptoError) -> PrivateKey

    /// Imports a private key from its raw byte representation.
    static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey

    /// Imports a public key from its raw byte representation.
    static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey

    /// Returns the public key corresponding to `privateKey`.
    static func publicKey(for privateKey: PrivateKey) -> PublicKey

    /// Serializes a private key to its raw byte representation.
    static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8]

    /// Serializes a public key to its raw byte representation.
    static func rawRepresentation(of publicKey: PublicKey) -> [UInt8]

    /// Computes the raw shared secret between `privateKey` and `peerPublicKey`.
    ///
    /// Key import rejects structurally or mathematically invalid bytes with
    /// ``CryptoError/invalidKeyMaterial``. This operation throws
    /// ``CryptoError/keyAgreementFailure`` only when agreement fails after both
    /// keys have already crossed their import boundaries.
    static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(CryptoError) -> [UInt8]
}
