/// Embedded-clean DTLS flight retransmission state (RFC 6347 §4.2.4).
///
/// The value-type engine owns the retry count, exponential-backoff policy, stale
/// timer generation, and retained plaintext flight recipe. It owns no clock, task,
/// lock, or I/O. A facade/transport driver sleeps for the exposed delay and calls
/// back with the generation it observed.
struct DTLSFlightController: Sendable {

    enum TimeoutPreparation: Sendable, Equatable {
        case retransmit(DTLSFlightRecipe)
        case superseded
    }

    private enum Mode: Sendable, Equatable {
        case idle
        case waiting
        case finalRetained
    }

    static var maxRetransmissions: Int { 6 }
    static var initialDelay: Duration { .seconds(1) }
    static var maximumDelay: Duration { .seconds(60) }

    private var mode: Mode = .idle
    private var flight: DTLSFlightRecipe?
    private var retransmissionCount: Int = 0
    private var currentDelay: Duration = Self.initialDelay
    private var generation: UInt64 = 0

    init() {}

    var retransmissionState: DTLSEngineRetransmissionState {
        DTLSEngineRetransmissionState(
            generation: generation,
            nextDelay: mode == .waiting ? currentDelay : nil
        )
    }

    /// Arms a new flight and invalidates every previously observed timer token.
    mutating func startFlight(_ recipe: DTLSFlightRecipe) {
        guard !recipe.isEmpty else { return }
        advanceGeneration()
        mode = .waiting
        flight = recipe
        retransmissionCount = 0
        currentDelay = Self.initialDelay
    }

    /// Retains the final flight without a timer so a duplicate peer flight can
    /// recover from a lost Finished after this endpoint considers itself connected.
    mutating func retainFinalFlight(_ recipe: DTLSFlightRecipe) {
        guard !recipe.isEmpty else { return }
        advanceGeneration()
        mode = .finalRetained
        flight = recipe
        retransmissionCount = 0
        currentDelay = Self.initialDelay
    }

    /// Acknowledges a complete next flight. Partial input and record anomalies must
    /// not call this method.
    mutating func responseCompleted() {
        advanceGeneration()
        mode = .idle
        flight = nil
        retransmissionCount = 0
        currentDelay = Self.initialDelay
    }

    /// Invalidates all pending timer tokens when the connection closes or fails.
    mutating func stop() {
        responseCompleted()
    }

    /// Validates one timeout token and advances the RTO generation before the
    /// engine performs any record encoding.
    mutating func prepareTimeout(
        generation expectedGeneration: UInt64
    ) throws(DTLSEngineError) -> TimeoutPreparation {
        guard expectedGeneration == generation,
              mode == .waiting,
              let flight else {
            return .superseded
        }
        guard retransmissionCount < Self.maxRetransmissions else {
            stop()
            throw .maxRetransmissionsExceeded
        }
        retransmissionCount += 1
        currentDelay = Self.doubledDelay(currentDelay)
        advanceGeneration()
        return .retransmit(flight)
    }

    /// A complete retransmission of the peer's previous flight requests an
    /// immediate resend of our retained flight. Waiting flights restart at the
    /// initial RTO; final retained flights remain timer-free.
    mutating func prepareDuplicateResponse() -> DTLSFlightRecipe? {
        guard let flight, mode != .idle else { return nil }
        if mode == .waiting {
            retransmissionCount = 0
            currentDelay = Self.initialDelay
        }
        advanceGeneration()
        return flight
    }

    @inline(__always)
    private mutating func advanceGeneration() {
        generation &+= 1
    }

    private static func doubledDelay(_ delay: Duration) -> Duration {
        let seconds = delay.components.seconds
        return .seconds(min(seconds * 2, maximumDelay.components.seconds))
    }
}
