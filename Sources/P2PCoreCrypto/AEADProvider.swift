// AEADProvider.swift
// Capability protocol: the three AEAD constructions a provider must supply
// (QUIC/TLS1.3 mandatory suites). A library that only needs authenticated
// encryption can be generic over `<C: AEADProvider>` instead of the full
// `CryptoProvider`. Embedded-clean: every primitive is an `associatedtype`.

/// The AEAD capability of a crypto backend.
///
/// AEADs are keyed factories: one `AEAD` value per derived key. Conforming a
/// provider to this capability alone is enough for record/packet protection that
/// does not also need hashing, key agreement, or signatures.
public protocol AEADProvider: Sendable {
    // AEAD constructions (QUIC/TLS1.3 mandatory suites)
    associatedtype AESGCM128:  AEAD
    associatedtype AESGCM256:  AEAD
    associatedtype ChaChaPoly: AEAD

    // AEADs are keyed factories (one value per derived key).
    static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> AESGCM128  // key 16
    static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> AESGCM256  // key 32
    static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> ChaChaPoly // key 32
}
