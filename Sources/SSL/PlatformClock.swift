import SSLCore

/// A caller-supplied wall clock used by certificate and ticket policy.
public typealias WallClock = SSLCore.WallClock

/// A caller-supplied monotonic clock used by retransmission and deadlines.
public typealias MonotonicClock = SSLCore.MonotonicClock

/// The target's realtime platform clock.
public typealias SystemWallClock = SSLCore.SystemWallClock

/// The target's process-wide monotonic platform clock.
public typealias SystemMonotonicClock = SSLCore.SystemMonotonicClock

/// A canonical wall-clock instant used by verification policy.
public typealias VerificationInstant = SSLCore.VerificationInstant

/// A canonical monotonic instant used by transport policy.
public typealias MonotonicInstant = SSLCore.MonotonicInstant

/// Failures reported by platform clocks.
public typealias ClockError = SSLCore.ClockError
