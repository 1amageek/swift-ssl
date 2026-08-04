// SignatureProvider.swift
// Capability protocol: the digital-signature schemes a provider must supply
// (Ed25519, ECDSA P-256, ECDSA P-384). Embedded-clean: every primitive is an
// `associatedtype`.

/// The signature capability of a crypto backend.
public protocol SignatureProvider: Sendable {
    // Signatures
    associatedtype Ed25519:       SignatureScheme
    associatedtype P256Signature: SignatureScheme
    associatedtype P384Signature: SignatureScheme

    /// Raw IEEE P1363 `r || s` P-256 scheme used below protocol wire codecs.
    /// Providers whose public P-256 scheme is already raw inherit that scheme.
    associatedtype RawP256Signature: SignatureScheme = P256Signature

    /// Raw IEEE P1363 `r || s` P-384 scheme used below protocol wire codecs.
    /// Providers whose public P-384 scheme is already raw inherit that scheme.
    associatedtype RawP384Signature: SignatureScheme = P384Signature
}
