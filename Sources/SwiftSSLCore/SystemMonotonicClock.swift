#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

/// Monotonic time supplied by the target's process-wide monotonic clock.
public struct SystemMonotonicClock: MonotonicClock, Sendable {
    private static let clockIdentifier: UInt64 = 0x5353_4C4D_4F4E_4F
    private static let ticksPerSecond: UInt64 = 1_000_000_000

    public init() {}

    public func now() throws(ClockError) -> MonotonicInstant {
        #if canImport(WASILibc)
        var ticks: __wasi_timestamp_t = 0
        let result = __wasi_clock_time_get(
            __wasi_clockid_t(1),
            1,
            &ticks
        )
        guard result == 0 else {
            throw .backendFailure(code: Int(result))
        }
        return try MonotonicInstant(
            clockIdentifier: Self.clockIdentifier,
            ticks: UInt64(ticks),
            ticksPerSecond: Self.ticksPerSecond
        )
        #elseif canImport(Darwin) || canImport(Glibc) || canImport(Musl)
        var value = timespec()
        let result = clock_gettime(CLOCK_MONOTONIC, &value)
        guard result == 0 else {
            throw .backendFailure(code: Int(errno))
        }
        guard
            let seconds = UInt64(exactly: value.tv_sec),
            let nanoseconds = UInt64(exactly: value.tv_nsec),
            nanoseconds < Self.ticksPerSecond
        else {
            throw .backendValueOutOfRange
        }
        guard seconds <= (UInt64.max - nanoseconds) / Self.ticksPerSecond else {
            throw .tickOverflow
        }
        let ticks = seconds * Self.ticksPerSecond + nanoseconds
        return try MonotonicInstant(
            clockIdentifier: Self.clockIdentifier,
            ticks: ticks,
            ticksPerSecond: Self.ticksPerSecond
        )
        #else
        throw .unavailable
        #endif
    }
}
