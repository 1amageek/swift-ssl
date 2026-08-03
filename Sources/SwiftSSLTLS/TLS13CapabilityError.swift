import SwiftSSLCore

public enum TLS13CapabilityError: Error, Sendable, Equatable {
  case noPendingRequest
  case duplicateResponse(TLS13CapabilityToken)
  case staleResponse(TLS13CapabilityToken)
  case wrongEngine(expected: OwnedBytes, actual: OwnedBytes)
  case wrongKind(expected: TLS13CapabilityKind, actual: TLS13CapabilityKind)
  case wrongSequence(expected: UInt64, actual: UInt64)
  case sequenceExhausted
  case wrongState
  case peerTrustRejected(TLS13PeerRole)
  case credentialUnavailable(TLSRole)
  case signatureRejected(TLSRole)
  case invalidCredential
}
