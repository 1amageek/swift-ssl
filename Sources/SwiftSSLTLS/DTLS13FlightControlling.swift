public protocol DTLS13FlightControlling: Sendable {
  var hasOutstandingFlight: Bool { get }
  var retransmissionCount: Int { get }

  mutating func startFlight(
    _ flight: consuming DTLS13Flight
  ) throws(DTLS13FlightError) -> DTLSActionBatch

  mutating func receiveAcknowledgment(
    _ acknowledgment: DTLS13Acknowledgment
  ) throws(DTLS13FlightError) -> DTLSActionBatch

  mutating func receiveImplicitAcknowledgment()
    throws(DTLS13FlightError) -> DTLSActionBatch

  mutating func retransmissionTimerExpired()
    throws(DTLS13FlightError) -> DTLSActionBatch
}
