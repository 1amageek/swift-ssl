// HashFunction.swift
// Cryptographic hash abstraction (SHA-256 / SHA-384); one-shot + incremental
// (TLS transcript). Embedded-clean: no `any`, no Foundation.

/// A cryptographic hash function with both one-shot and incremental use.
///
/// Conforming types are value types representing the running hash state.
/// `finalize()` is `consuming` because the hash state is single-use (A6).
public protocol HashFunction: Sendable {
    /// The digest length in bytes (32 for SHA-256, 48 for SHA-384).
    static var digestLength: Int { get }

    /// The input block size in bytes (64 / 128, for HMAC/HKDF block sizing).
    static var blockLength: Int { get }

    /// Creates an empty hash state.
    init()

    /// Feeds more bytes into the running hash.
    mutating func update(_ data: Span<UInt8>)

    /// Finalizes the hash and returns the digest of length ``digestLength``.
    consuming func finalize() -> [UInt8]
}

extension HashFunction {
    /// Computes the digest of a single buffer in one call.
    public static func hash(_ data: Span<UInt8>) -> [UInt8] {
        var function = Self()
        function.update(data)
        return function.finalize()
    }
}
