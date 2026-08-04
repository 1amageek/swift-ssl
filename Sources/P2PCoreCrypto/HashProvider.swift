// HashProvider.swift
// Capability protocol: the SHA-256 / SHA-384 hashes a provider must supply
// (TLS transcript, HKDF backing, libp2p identity). Embedded-clean: every
// primitive is an `associatedtype`.

/// The hash capability of a crypto backend.
///
/// Both hashes are exposed as `associatedtype`s so a generic upper layer
/// specialises cleanly under Embedded Swift (no `any`). ``KDFProvider`` refines
/// this protocol so its HKDF types can be hash-bound to ``SHA256`` / ``SHA384``.
public protocol HashProvider: Sendable {
    // Hashes
    associatedtype SHA256: HashFunction
    associatedtype SHA384: HashFunction
}
