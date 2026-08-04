// CryptoError.swift
// Typed errors for the crypto seam. Embedded-clean: no Foundation, no `any`.

/// Errors raised by the crypto primitive protocols.
///
/// Concrete providers (M4) map backend errors onto these cases. **No silent
/// fallback**: a tag mismatch is ``authenticationFailure``, never a return of
/// empty/garbage plaintext.
public enum CryptoError: Error, Equatable, Sendable {
    /// AEAD tag mismatch — never a silent empty/garbage return.
    case authenticationFailure

    /// Wrong key/nonce/tag/expand length.
    case invalidLength(expected: Int, actual: Int)

    /// Suite/curve not offered by this provider.
    case unsupportedParameter

    /// Diffie-Hellman produced no shared secret.
    case keyAgreementFailure

    /// A key had the expected byte length but was not valid for its algorithm.
    ///
    /// Examples include a zero/out-of-range NIST-curve scalar and a malformed,
    /// off-curve, infinite, or non-canonical public point. This is distinct from
    /// ``keyAgreementFailure``, which describes a failure while deriving a
    /// shared secret from already-imported keys.
    case invalidKeyMaterial

    /// Reserved; verify uses `Bool`, sign may throw this.
    case invalidSignature

    /// The selected cryptographic engine failed.
    case providerFailure
}
