// KeyDerivation.swift
// HKDF (RFC 5869), hash-bound by associatedtype. Embedded-clean: no `any`.

/// HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
///
/// Bound to a concrete ``HashFunction`` through the ``Hash`` associatedtype so it
/// specialises cleanly under Embedded Swift (no `any`).
public protocol KeyDerivation: Sendable {
    /// The hash backing the HMAC used by both phases.
    associatedtype Hash: HashFunction

    /// Creates a derivation context.
    init()

    /// HKDF-Extract: derives a pseudorandom key of length `Hash.digestLength`.
    func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8]

    /// HKDF-Expand: expands `prk` into `length` bytes of output keying material.
    ///
    /// - Throws: ``CryptoError/invalidLength(expected:actual:)`` if
    ///   `length > 255 * Hash.digestLength`.
    func expand(
        prk: Span<UInt8>,
        info: Span<UInt8>,
        length: Int
    ) throws(CryptoError) -> [UInt8]
}
