// HeaderProtectionProviding.swift
// Capability protocol: the QUIC header-protection primitive a provider supplies
// (RFC 9001 §5.4). Named `HeaderProtectionProviding` (not
// `HeaderProtectionProvider`) to avoid colliding with the primitive protocol
// `HeaderProtectionProvider` that its associatedtype conforms to. Embedded-clean:
// the primitive is an `associatedtype`, never `any`.

/// The header-protection capability of a crypto backend.
public protocol HeaderProtectionProviding: Sendable {
    associatedtype HeaderProtection: HeaderProtectionProvider
}
