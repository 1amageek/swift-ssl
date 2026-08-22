import SSLCore
import TLSTypes

/// The result of opening one application-era record into caller-owned storage.
///
/// Application data occupies the reported prefix of the unpublished
/// destination. Protocol-control records retain their own state only when the
/// handshake engine must continue processing after this synchronous call.
public enum TLS13StreamRecordDestinationTransition: ~Copyable, Sendable {
  case applicationData(byteCount: Int)
  case postHandshake(TLS13StreamHandshakeTransition)
  case sessionTicket(TLS13ResumptionState)
  case alert(TLSAlert)
}
