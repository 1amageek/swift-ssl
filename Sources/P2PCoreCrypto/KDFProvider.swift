// KDFProvider.swift
// Capability protocol: the HKDF-SHA256 / HKDF-SHA384 derivations a provider must
// supply. Refines `HashProvider` so each HKDF type is hash-bound to the matching
// SHA primitive by a same-type constraint (A7). Embedded-clean: every primitive
// is an `associatedtype`.

/// The key-derivation capability of a crypto backend.
///
/// Refines ``HashProvider`` so ``HKDFSHA256`` / ``HKDFSHA384`` can be bound to
/// ``HashProvider/SHA256`` / ``HashProvider/SHA384`` through the
/// `where Hash == ...` constraints, exactly as the aggregate did.
public protocol KDFProvider: HashProvider {
    // Key derivation, hash-bound by same-type constraints (A7)
    associatedtype HKDFSHA256: KeyDerivation where HKDFSHA256.Hash == SHA256
    associatedtype HKDFSHA384: KeyDerivation where HKDFSHA384.Hash == SHA384
}
