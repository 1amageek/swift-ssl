import SwiftSSLCore

/// A caller-supplied wall clock used by certificate and ticket policy.
public typealias WallClock = SwiftSSLCore.WallClock

/// A caller-supplied monotonic clock used by retransmission and deadlines.
public typealias MonotonicClock = SwiftSSLCore.MonotonicClock

/// The target's realtime platform clock.
public typealias SystemWallClock = SwiftSSLCore.SystemWallClock

/// The target's process-wide monotonic platform clock.
public typealias SystemMonotonicClock = SwiftSSLCore.SystemMonotonicClock

/// A canonical wall-clock instant used by verification policy.
public typealias VerificationInstant = SwiftSSLCore.VerificationInstant

/// A canonical monotonic instant used by transport policy.
public typealias MonotonicInstant = SwiftSSLCore.MonotonicInstant

/// Failures reported by platform clocks.
public typealias ClockError = SwiftSSLCore.ClockError
