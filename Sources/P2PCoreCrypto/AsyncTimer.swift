// AsyncTimer.swift
// The timer seam that lets an Embedded-clean async connection driver schedule
// timeouts / retransmission WITHOUT `Task.sleep` or `ContinuousClock` (both
// `@available(*, unavailable)` under Embedded Swift 6.3.1).
//
// It REFINES the existing `MonotonicClock` time source rather than introducing a
// second, competing clock: `MonotonicClock` already provides the monotonic nanos
// (`monotonicNanos()`), and a driver that schedules deadlines needs exactly that
// plus a way to suspend until a deadline. `AsyncTimer` adds only the latter, so
// the codebase keeps ONE clock story — time comes from `MonotonicClock`, and a
// driver injects an `AsyncTimer` (which IS a `MonotonicClock`).
//
// Embedded-clean by construction:
//   * no `any` (drivers inject a concrete `T: AsyncTimer`)
//   * no Foundation, no `ContinuousClock`, no `Date`
//   * `sleep` is typed-throws `CancellationError` ONLY — an untyped `throws`
//     (i.e. `any Error`) crosses the async boundary as an existential, which
//     fails to compile under Embedded (de-risk probe T*/#12).

import _Concurrency   // REQUIRED under Embedded for `async`/`CancellationError` (probe P10)

/// A monotonic clock that can also suspend the current task until a deadline.
///
/// This is the single time+sleep seam an async connection driver injects. The
/// driver reads deadlines as monotonic nanoseconds from its cored value-type
/// state machines (PTO, idle timeout, pacing), computes the nearest one, and
/// calls ``sleep(untilNanos:)`` to park until it elapses — never `Task.sleep`,
/// never `ContinuousClock`.
///
/// Conformers inherit the time surface from ``MonotonicClock``:
/// ``MonotonicClock/monotonicNanos()`` is the "now" used to compute the wait,
/// so there is no second, separate "now" on this protocol.
///
/// ## The executor / timer is the embedder's runtime on Embedded
///
/// Embedded Swift ships no default global executor and no time source by design
/// (the concurrency runtime is the embedder's responsibility). The host
/// implementation backs ``sleep(untilNanos:)`` with `ContinuousClock` +
/// `Task.sleep`; the Embedded/POSIX reference backs it with `clock_gettime` +
/// a blocking wait, but a production embedder is expected to supply its own
/// ``AsyncTimer`` whose ``sleep(untilNanos:)`` parks the task on the platform's
/// real timer/executor rather than blocking a thread.
public protocol AsyncTimer: MonotonicClock {
    /// Suspends the current task until the monotonic clock reaches `deadlineNanos`.
    ///
    /// The deadline is an absolute value on the SAME monotonic timeline as
    /// ``MonotonicClock/monotonicNanos()``. If the deadline is already in the
    /// past, the call returns promptly (no spurious wait).
    ///
    /// - Parameter deadlineNanos: The absolute monotonic-nanoseconds instant to
    ///   wake at, as produced by ``MonotonicClock/monotonicNanos()``.
    /// - Throws: ``CancellationError`` — and ONLY ``CancellationError`` — if the
    ///   task is cancelled while suspended. The typed throw is deliberate: an
    ///   untyped `throws` would erase to `any Error` across the async boundary,
    ///   which is rejected under Embedded Swift.
    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError)
}
