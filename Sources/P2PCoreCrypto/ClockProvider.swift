// ClockProvider.swift
// Capability protocol: the ambient monotonic clock a provider exposes as a
// static singleton (timers/RTT/loss detection). Embedded-clean: the clock is an
// `associatedtype`, never `any`.

/// The monotonic-time capability of a crypto backend.
///
/// Exposes the provider's clock as a static singleton (no provider instance
/// state) so it specialises trivially under Embedded Swift.
public protocol ClockProvider: Sendable {
    associatedtype Clock: MonotonicClock
    static var clock: Clock { get }
}
