#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

/// Wall-clock time supplied by the target's realtime platform clock.
public struct SystemWallClock: WallClock, Sendable {
    public init() {}

    public func now() throws(ClockError) -> VerificationInstant {
        #if canImport(WASILibc)
        var ticks: __wasi_timestamp_t = 0
        let result = __wasi_clock_time_get(
            __wasi_clockid_t(0),
            1,
            &ticks
        )
        guard result == 0 else {
            throw .backendFailure(code: Int(result))
        }
        let nanosecondsPerSecond: UInt64 = 1_000_000_000
        let seconds = ticks / nanosecondsPerSecond
        guard let canonicalSeconds = Int64(exactly: seconds) else {
            throw .backendValueOutOfRange
        }
        return try VerificationInstant(
            secondsSinceUnixEpoch: canonicalSeconds,
            nanoseconds: UInt32(ticks % nanosecondsPerSecond)
        )
        #elseif canImport(Darwin) || canImport(Glibc) || canImport(Musl)
        var value = timespec()
        let result = clock_gettime(CLOCK_REALTIME, &value)
        guard result == 0 else {
            throw .backendFailure(code: Int(errno))
        }
        guard
            let seconds = Int64(exactly: value.tv_sec),
            let nanoseconds = UInt32(exactly: value.tv_nsec),
            nanoseconds < 1_000_000_000
        else {
            throw .backendValueOutOfRange
        }
        return try VerificationInstant(
            secondsSinceUnixEpoch: seconds,
            nanoseconds: nanoseconds
        )
        #else
        throw .unavailable
        #endif
    }
}
