/// The Embedded-clean generic DTLS 1.2 record protector (RFC 5288 — AES-GCM).
///
/// DTLS 1.2 uses explicit-nonce AEAD construction:
/// ```
/// nonce = fixed_IV (4) || explicit_nonce (8)        // explicit_nonce = epoch(2) || seq(6)
/// AAD   = epoch || seq_num || content_type || version || plaintext_length
/// output = explicit_nonce (8) || ciphertext || tag (16)
/// ```
/// This differs from TLS 1.3 (implicit `iv XOR seq`); the AAD and explicit nonce
/// are constructed by the caller (the adapter builds them from the record header)
/// and passed in as values, so this core holds no sequence/epoch state and no
/// `Mutex` — Embedded-clean.
///
/// `DTLSRecordProtector<C, A>` carries one keyed AEAD `A: AEAD` plus the 4-byte
/// fixed IV, mirroring the proven QUIC ``QUICPacketProtectionCore/PacketProtector``
/// (AEAD + IV value type sealing/opening over the `CryptoProvider.AEAD` seam). The
/// adapter holds one protector per direction (write key / read key).
///
/// AEAD-open failure throws ``DTLSRecordProtectionError/decryptionFailed`` — no
/// silent fallback, never a garbage/empty plaintext.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

public struct DTLSRecordProtector<C: CryptoProvider, A: AEAD>: Sendable {
    private let implementation: DTLSAEADRecordProtector
    private let aeadValue: A

    /// The keyed AEAD for this direction.
    public var aead: A { aeadValue }

    /// The 4-byte fixed IV (from the DTLS key block).
    public var fixedIV: [UInt8] { implementation.fixedIV }

    /// The fixed-IV length for DTLS 1.2 AES-GCM (RFC 5288).
    public static var fixedIVLength: Int {
        DTLSAEADRecordProtector.fixedIVLength
    }

    /// The explicit-nonce length (epoch(2) || seq(6)).
    public static var explicitNonceLength: Int {
        DTLSAEADRecordProtector.explicitNonceLength
    }

    /// The AEAD authentication tag length (16 bytes).
    public static var tagLength: Int {
        A.tagLength
    }

    /// Creates a protector from a keyed AEAD and the 4-byte fixed IV.
    ///
    /// - Throws: ``DTLSRecordProtectionError/invalidFixedIVLength(expected:actual:)``
    ///   if `fixedIV` is not 4 bytes.
    public init(
        aead: A,
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) {
        self.aeadValue = aead
        self.implementation = try DTLSAEADRecordProtector(
            fixedIV: fixedIV,
            authenticationTagLength: A.tagLength,
            seal: { @Sendable (
                plaintext: Span<UInt8>,
                nonce: [UInt8],
                aad: [UInt8]
            ) throws(CryptoError) -> [UInt8] in
                try aead.seal(
                    plaintext,
                    nonce: nonce.span,
                    aad: aad.span
                )
            },
            open: { @Sendable (
                ciphertext: Span<UInt8>,
                nonce: [UInt8],
                aad: [UInt8]
            ) throws(CryptoError) -> [UInt8] in
                try aead.open(
                    ciphertext,
                    nonce: nonce.span,
                    aad: aad.span
                )
            }
        )
    }

    // MARK: - Seal (encrypt)

    /// Seals `plaintext` for the given `explicitNonce` (8 bytes) and `aad`.
    ///
    /// - Returns: `explicit_nonce (8) || ciphertext || tag (16)`.
    public func seal(
        plaintext: Span<UInt8>,
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        try implementation.seal(
            plaintext: plaintext,
            explicitNonce: explicitNonce,
            aad: aad
        )
    }

    // MARK: - Open (decrypt)

    /// Opens a DTLS ciphertext (`explicit_nonce (8) || ciphertext || tag (16)`)
    /// for the given `aad`, recovering the plaintext.
    ///
    /// Throws ``DTLSRecordProtectionError/decryptionFailed(_:)`` on any AEAD-open
    /// failure — no silent fallback, never a garbage plaintext.
    public func open(
        ciphertext: Span<UInt8>,
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        try implementation.open(ciphertext: ciphertext, aad: aad)
    }
}
