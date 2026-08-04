// AEAD.swift
// Authenticated Encryption with Associated Data. QUIC packet protection
// (RFC 9001 §5.3), TLS record protection. Embedded-clean: no `any`, no Foundation.

/// An authenticated encryption primitive bound to a single key.
///
/// - `seal` returns `ciphertext || tag` (`plaintext.count + tagLength` bytes).
/// - `open` consumes `ciphertext || tag`; returns plaintext
///   (`ciphertext.count - tagLength`); throws ``CryptoError/authenticationFailure``
///   on tag mismatch, ``CryptoError/invalidLength(expected:actual:)`` if the input
///   is shorter than `tagLength`.
///
/// Inputs are borrowed `Span<UInt8>`; outputs are owned `[UInt8]`. Conforming
/// types are `Sendable` values (one per derived key).
public protocol AEAD: Sendable {
    /// The nonce length in bytes (12 for AES-GCM and ChaCha20-Poly1305).
    static var nonceLength: Int { get }

    /// The authentication tag length in bytes (16).
    static var tagLength: Int { get }

    /// Encrypts `plaintext` and authenticates it together with `aad`.
    func seal(
        _ plaintext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8]

    /// Decrypts and authenticates `ciphertext` against `aad`.
    func open(
        _ ciphertext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8]
}
