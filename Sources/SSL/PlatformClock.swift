import SSLCore
import NetworkingTime

#if canImport(Darwin) || canImport(Glibc) || canImport(Musl)
import NetworkingPOSIX
#elseif canImport(WASILibc)
import NetworkingWASI
#endif

/// A caller-supplied wall clock used by certificate and ticket policy.
public typealias WallClock = NetworkingTime.WallClock

/// A caller-supplied monotonic clock used by retransmission and deadlines.
public typealias MonotonicClock = NetworkingTime.MonotonicClock

/// The target's realtime platform clock.
#if canImport(Darwin) || canImport(Glibc) || canImport(Musl)
public typealias SystemWallClock = NetworkingPOSIX.POSIXWallClock
#elseif canImport(WASILibc)
public typealias SystemWallClock = NetworkingWASI.WASIWallClock
#endif

/// The target's process-wide monotonic platform clock.
#if canImport(Darwin) || canImport(Glibc) || canImport(Musl)
public typealias SystemMonotonicClock = NetworkingPOSIX.POSIXMonotonicClock
#elseif canImport(WASILibc)
public typealias SystemMonotonicClock = NetworkingWASI.WASIMonotonicClock
#endif

/// A canonical wall-clock instant used by verification policy.
public typealias VerificationInstant = SSLCore.VerificationInstant

/// A canonical monotonic instant used by transport policy.
public typealias MonotonicInstant = NetworkingTime.MonotonicInstant

/// Failures reported by platform clocks.
public typealias ClockError = NetworkingTime.TimeError

#if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(WASILibc)
func makeSystemWallClock() -> any WallClock {
#if canImport(Darwin) || canImport(Glibc) || canImport(Musl)
  return NetworkingPOSIX.POSIXWallClock()
#elseif canImport(WASILibc)
  return NetworkingWASI.WASIWallClock()
#endif
}
#endif
