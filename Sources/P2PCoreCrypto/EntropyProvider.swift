// EntropyProvider.swift
// Capability protocol: the ambient CSPRNG a provider exposes as a static
// singleton. Embedded-clean: the source is an `associatedtype`, never `any`.

/// The randomness capability of a crypto backend.
///
/// Exposes the provider's CSPRNG as a static singleton (no provider instance
/// state) so it specialises trivially under Embedded Swift.
public protocol EntropyProvider: Sendable {
    associatedtype Random: RandomSource
    static var random: Random { get }
}
