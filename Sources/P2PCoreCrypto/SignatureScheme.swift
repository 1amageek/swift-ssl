// SignatureScheme.swift
// Ed25519, ECDSA P-256, ECDSA P-384. libp2p identity + TLS CertificateVerify.
// Embedded-clean: no `any`, no Foundation.

/// A digital signature scheme (Ed25519, ECDSA P-256, or ECDSA P-384).
///
/// Key material is modelled with `associatedtype`s so the scheme specialises
/// cleanly under Embedded Swift (no `any`). Concrete key types are defined by the
/// provider (M4).
public protocol SignatureScheme: Sendable {
    /// A signing (private) key.
    associatedtype SigningKey: Sendable

    /// A verifying (public) key.
    associatedtype VerifyingKey: Sendable

    /// Generates a fresh signing key using the provider's secure RNG.
    static func generateSigningKey() throws(CryptoError) -> SigningKey

    /// Imports a signing key from its raw byte representation.
    static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey

    /// Imports a verifying key from its raw byte representation.
    static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey

    /// Returns the verifying key corresponding to `signingKey`.
    static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey

    /// Serializes a signing key to its raw byte representation.
    static func rawRepresentation(of signingKey: SigningKey) -> [UInt8]

    /// Serializes a verifying key to its raw byte representation.
    static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8]

    /// Signs `message` with `signingKey`.
    static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8]

    /// Verifies `signature` over `message` against `verifyingKey`.
    static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool
}
