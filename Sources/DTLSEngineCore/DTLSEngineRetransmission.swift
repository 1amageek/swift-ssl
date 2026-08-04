/// Caller-driven DTLS flight retransmission state.
///
/// The sans-I/O engine owns the protocol retry policy and generation token but
/// never reads a clock or starts a task. A driver sleeps for `nextDelay`, then
/// passes `generation` back to `handleTimeout(generation:)`. A stale generation
/// is rejected without changing engine state or emitting a datagram.
public struct DTLSEngineRetransmissionState: Sendable, Equatable {
    public let generation: UInt64
    public let nextDelay: Duration?

    public init(generation: UInt64, nextDelay: Duration?) {
        self.generation = generation
        self.nextDelay = nextDelay
    }
}

/// Result of attempting one caller-driven retransmission timeout.
public enum DTLSEngineTimeoutResult: Sendable, Equatable {
    /// The generation was current and the complete flight was re-encoded with
    /// fresh record sequence numbers. `next` describes the replacement timer.
    case retransmit(datagrams: [[UInt8]], next: DTLSEngineRetransmissionState)

    /// The supplied generation no longer owns the timer. No datagram was encoded
    /// and no retransmission counter changed.
    case superseded(current: DTLSEngineRetransmissionState)
}
