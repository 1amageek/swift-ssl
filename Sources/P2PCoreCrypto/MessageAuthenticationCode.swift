// MessageAuthenticationCode.swift
// HMAC. STUN uses HMAC-SHA1; QUIC/TLS/Noise use SHA-256/384. Embedded-clean.

/// A message authentication code (HMAC) with one-shot, incremental, and
/// constant-time verification interfaces.
public protocol MessageAuthenticationCode: Sendable {
    /// The MAC length in bytes (equals the underlying `Hash.digestLength`).
    static var macLength: Int { get }

    /// Creates a keyed MAC context.
    init(key: Span<UInt8>)

    /// Feeds more bytes into the running MAC.
    mutating func update(_ data: Span<UInt8>)

    /// Finalizes the MAC and returns the code of length ``macLength``.
    consuming func finalize() -> [UInt8]

    /// One-shot convenience: the MAC of `message` under `key`.
    static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8]

    /// Constant-time verification of `mac` over `message` under `key`.
    static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool
}
