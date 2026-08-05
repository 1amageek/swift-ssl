import SSLCore
import TLSTypes

/// The classified result of one encrypted TLS 1.3 application-era record.
///
/// The record protector remains owned by the handshake engine. Callers receive
/// either borrowed protocol effects wrapped in an owned transition, decrypted
/// application bytes, or an authenticated alert classification.
public enum TLS13StreamRecordTransition: ~Copyable, Sendable {
  case applicationData(OwnedBytes)
  case postHandshake(TLS13StreamHandshakeTransition)
  case sessionTicket(TLS13ResumptionState)
  case alert(TLSAlert)
}
