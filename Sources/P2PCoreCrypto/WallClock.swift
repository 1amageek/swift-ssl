// WallClock.swift
// The wall-clock (calendar) time seam, SEPARATE from the monotonic `MonotonicClock`.
//
// `MonotonicClock` answers "how much time has elapsed" from an arbitrary fixed
// origin (≈ process/timer start) — correct for deadlines, RTT and loss detection,
// but NOT a calendar time: a value derived from it looks like it was produced in
// ~1970 (a few seconds past the origin). A certificate's notBefore / notAfter MUST
// be real Unix-epoch wall-clock seconds so a remote peer's validity check accepts
// it; deriving them from the monotonic clock makes the cert look issued in 1970 and
// external go-libp2p / rust-libp2p peers reject it.
//
// `WallClock` therefore provides ONLY the calendar "now" (Unix epoch seconds), kept
// deliberately distinct from `MonotonicClock`/`AsyncTimer` so the two time stories
// never get conflated again. A driver keeps using the monotonic clock for deadlines
// and injects a `WallClock` for any value that must be a real timestamp.
//
// FAIL-CLOSED on Embedded: there is no implicit fallback to monotonic time. Embedded
// Swift ships no default calendar clock (Foundation `Date` is unavailable), so the
// embedder MUST inject a `WallClock` backed by the device RTC. If a valid timestamp
// cannot be produced, the caller surfaces an explicit error rather than minting a
// cert dated ~1970.
//
// Embedded-clean: no `any`, no Foundation, no `Date`. Conformers are concrete
// (`T: WallClock`), so a generic upper layer specialises cleanly under Embedded.

/// A calendar (wall-clock) time source, distinct from ``MonotonicClock``.
///
/// Use this — never ``MonotonicClock`` — for any value that must be a real
/// timestamp (e.g. an X.509 certificate's notBefore / notAfter). The monotonic
/// clock measures elapsed time from an arbitrary origin and is NOT a calendar time.
public protocol WallClock: Sendable {
    /// The current wall-clock time as Unix epoch seconds (seconds since
    /// 1970-01-01T00:00:00Z).
    ///
    /// On host this is the real system clock; on Embedded the embedder supplies a
    /// device-RTC-backed value. It is the caller's responsibility to provide a
    /// correct clock — there is no silent fallback to monotonic time.
    func nowUnixSeconds() -> Int64
}
