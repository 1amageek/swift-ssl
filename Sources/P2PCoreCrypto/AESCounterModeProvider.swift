// AESCounterModeProvider.swift
// Narrow capability seam for protocols that require AES-128-CTR.

/// A provider of reusable AES-128 counter-mode cipher contexts.
///
/// This capability intentionally remains independent of ``CryptoProvider``.
/// Protocols such as SRTP can require exactly
/// `AESCounterModeProvider & MACProvider` without forcing unrelated TLS, QUIC,
/// or Noise providers to implement AES-CTR.
public protocol AESCounterModeProvider {
    associatedtype AES128CounterMode: AESCounterModeCipher

    /// Creates a reusable AES-128 counter-mode cipher context.
    static func makeAES128CounterMode(
        key: Span<UInt8>
    ) throws(AESCounterModeError) -> AES128CounterMode
}

extension AESCounterModeProvider {
    public static func makeAES128CounterMode(
        key: Span<UInt8>
    ) throws(AESCounterModeError) -> AES128CounterMode {
        try AES128CounterMode(key: key)
    }
}
