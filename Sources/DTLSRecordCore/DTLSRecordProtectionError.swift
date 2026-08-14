/// Typed errors for the Embedded-clean DTLS 1.2 record-protection core.
///
/// Embedded-clean: no Foundation, no `any`, no `String` payloads (so the enum is
/// `Equatable`). AEAD failures from ``SSLCryptoContracts/AEADError`` are surfaced
/// rather than swallowed — there is
/// **no silent fallback**: an open failure throws ``decryptionFailed``, never a
/// garbage/empty plaintext. The adapter bridges these to the existing
/// `DTLSRecordError` (`encryptionFailed`/`decryptionFailed` with messages) so the
/// public behavior is unchanged.

import SSLCryptoContracts

/// Errors raised by DTLS record protection contexts.
public enum DTLSRecordProtectionError: Error, Equatable, Sendable {
    /// A keyed cipher was constructed with an unsupported key length.
    case invalidKeyLength(expected: [Int], actual: Int)

    /// The fixed IV passed at construction was not 4 bytes (RFC 5288).
    case invalidFixedIVLength(expected: Int, actual: Int)

    /// The explicit nonce passed to `seal` was not 8 bytes.
    case invalidExplicitNonceLength(expected: Int, actual: Int)

    /// The ciphertext was shorter than explicit-nonce + tag overhead.
    case ciphertextTooShort(minimum: Int, actual: Int)

    /// A negative plaintext length reached the size calculation boundary.
    case invalidPlaintextLength(actual: Int)

    /// Plaintext and overhead could not be added without overflowing `Int`.
    case outputLengthOverflow(plaintextByteCount: Int, recordOverhead: Int)

    /// Caller-owned output does not exactly match the required record size.
    case invalidOutputLength(expected: Int, actual: Int)

    /// AEAD decryption/authentication failed. Uniform surface — does not leak why
    /// the record was rejected (RFC 6347 §4.1.2.7).
    case decryptionFailed

    /// A seal primitive failed. Seal failures are not security-sensitive and are
    /// reported precisely, unlike open failures.
    case encryptionFailed(AEADError)
}
