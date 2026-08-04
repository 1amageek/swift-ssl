// RandomSource.swift
// CSPRNG seam (replaces Foundation; STUN tx-id, QUIC CIDs, key gen).
// Embedded-clean: no `any`, no Foundation.

/// A cryptographically secure random byte source.
public protocol RandomSource: Sendable {
    /// Returns `count` fresh random bytes.
    func randomBytes(_ count: Int) -> [UInt8]

    /// Fills `buffer` in place with fresh random bytes.
    func fill(_ buffer: inout [UInt8])
}
