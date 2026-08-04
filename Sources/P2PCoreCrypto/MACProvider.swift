// MACProvider.swift
// Capability protocol: the HMAC primitives a provider must supply (STUN = SHA1;
// QUIC/TLS/Noise = SHA256/384). Embedded-clean: every primitive is an
// `associatedtype`.

/// The message-authentication capability of a crypto backend.
public protocol MACProvider: Sendable {
    // Message authentication (STUN = SHA1; QUIC/TLS/Noise = SHA256/384)
    associatedtype HMACSHA1:   MessageAuthenticationCode
    associatedtype HMACSHA256: MessageAuthenticationCode
    associatedtype HMACSHA384: MessageAuthenticationCode
}
