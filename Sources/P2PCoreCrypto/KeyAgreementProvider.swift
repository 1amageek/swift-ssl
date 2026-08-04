// KeyAgreementProvider.swift
// Capability protocol: the ECDH schemes a provider must supply (X25519, P-256,
// P-384). Embedded-clean: every primitive is an `associatedtype`.

/// The key-agreement capability of a crypto backend.
public protocol KeyAgreementProvider: Sendable {
    // Key agreement
    associatedtype X25519:        KeyAgreement
    associatedtype P256Agreement: KeyAgreement
    associatedtype P384Agreement: KeyAgreement
}
