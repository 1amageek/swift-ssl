// MonotonicClock.swift
// Replaces Foundation Date/ProcessInfo for timers/RTT/loss detection.
// Embedded-clean: no `any`, no Foundation.

/// A monotonic time source for timers, RTT, and loss detection.
public protocol MonotonicClock: Sendable {
    /// Milliseconds since an arbitrary fixed epoch (monotonic).
    func monotonicMillis() -> UInt64

    /// Nanoseconds, for fine-grained RTT/pacing (monotonic).
    func monotonicNanos() -> UInt64
}
