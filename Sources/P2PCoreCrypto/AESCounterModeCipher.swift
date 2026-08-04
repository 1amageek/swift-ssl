// AESCounterModeCipher.swift
// In-place AES-128-CTR primitive for protocols such as SRTP.

/// A reusable AES-128 counter-mode cipher context.
///
/// The context owns key-derived backend state. `applyKeystream` mutates only the
/// requested range of the caller-owned buffer, so packet payloads are not
/// materialized into an intermediate allocation. The counter is borrowed for
/// the duration of the call and is never retained.
///
/// AES-CTR provides confidentiality only. Callers are responsible for applying
/// the authentication construction required by their protocol.
public protocol AESCounterModeCipher: Sendable {
    /// Creates a reusable AES-128 cipher context from a 16-byte key.
    init(key: Span<UInt8>) throws(AESCounterModeError)

    /// XORs the AES-CTR keystream into `bytes[range]` in place.
    ///
    /// - Parameters:
    ///   - bytes: The caller-owned buffer to mutate.
    ///   - range: The exact subrange protected by this operation. Bytes outside
    ///     the range remain unchanged.
    ///   - initialCounter: The 16-byte initial counter block. Incrementing the
    ///     counter during the operation does not mutate this borrowed input.
    func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError)
}
