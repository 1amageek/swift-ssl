// HeaderProtectionProvider.swift
// QUIC header protection (RFC 9001 §5.4). Resolved mask form
// (crypto-embedded.md §1.2): returns the 5-byte HP mask directly.
// AES path = single-block AES-ECB on the 16-byte sample; ChaCha path = RFC 8439
// block, counter = sample[0..<4] LE, nonce = sample[4..<16], first 5 keystream
// bytes. Embedded-clean: no `any`, no Foundation.
public protocol HeaderProtectionProvider: Sendable {
    /// Returns the 5-byte AES-ECB header-protection mask for `sample` under `key`.
    static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8]

    /// Returns the 5-byte ChaCha20 header-protection mask for `sample` under `key`.
    static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8]
}
