// AESCounterModeError.swift
// Typed failures for the AES-128 counter-mode capability.

/// Errors raised by an AES-128 counter-mode cipher.
///
/// AES-CTR does not authenticate its input. Authentication failures therefore
/// belong to the protocol using this capability, such as SRTP, rather than to
/// this primitive.
public enum AESCounterModeError: Error, Equatable, Sendable {
    /// AES-128 requires a 16-byte key.
    case invalidKeyLength(expected: Int, actual: Int)

    /// The initial counter block must be exactly 16 bytes.
    case invalidCounterLength(expected: Int, actual: Int)

    /// The requested mutation range is outside the owned byte buffer.
    case invalidRange(lowerBound: Int, upperBound: Int, bufferCount: Int)

    /// The selected cryptography backend could not create or operate its cipher.
    case providerFailure
}
