// CryptoProvider.swift
// Aggregating seam that the QUIC/TLS stack depends on instead of swift-crypto.
// Embedded-clean: every primitive is an `associatedtype`, never `any`.

/// The single dependency-inversion seam between the QUIC/TLS stack and a concrete
/// cryptography backend.
///
/// `CryptoProvider` is a pure *composition* of the capability sub-protocols
/// (``AEADProvider``, ``KDFProvider``, ``MACProvider``, ``KeyAgreementProvider``,
/// ``SignatureProvider``, ``EntropyProvider``, ``ClockProvider``,
/// ``HeaderProtectionProviding``). It adds no requirements of its own — the same
/// 19 `associatedtype`s and their factory members are now grouped under the
/// capability protocols, so:
///
/// - Anything generic over `<C: CryptoProvider>` keeps working unchanged: the
///   aggregate still surfaces every member through protocol refinement.
/// - A library that needs only a slice of the surface can be generic over that
///   slice (`<C: AEADProvider & KDFProvider & KeyAgreementProvider>` for Noise),
///   which is both self-documenting and conformable in isolation.
/// - The default provider (`DefaultCryptoProvider`, in the `P2PCrypto` product) conforms
///   to the full aggregate, so the facades still specialise at a single `C`.
///
/// All primitives are exposed as `associatedtype`s rather than `any`-typed
/// values, so a generic upper layer specialises cleanly under Embedded Swift.
public protocol CryptoProvider:
    AEADProvider,
    KDFProvider,
    MACProvider,
    KeyAgreementProvider,
    SignatureProvider,
    EntropyProvider,
    ClockProvider,
    HeaderProtectionProviding {}
