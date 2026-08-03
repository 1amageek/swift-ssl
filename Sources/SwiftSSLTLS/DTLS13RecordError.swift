import SwiftSSLCore

public enum DTLS13RecordError: Error, Sendable, Equatable {
  case byte(ByteError)
  case malformedRecord
  case unsupportedContentType(UInt8)
  case invalidLegacyVersion(UInt16)
  case invalidEpoch(UInt64)
  case invalidSequenceNumber(UInt64)
  case invalidTruncatedSequenceNumber(bitCount: Int, value: UInt64)
  case connectionIDMismatch
  case recordTooLarge(limit: Int, actual: Int)
  case outputTooSmall(required: Int, actual: Int)
  case overlappingInputAndOutput
  case authenticationFailed
  case replayed(DTLS13RecordNumber)
  case tooOld(DTLS13RecordNumber)
  case replay(DTLS13ReplayError)
  case keyMaterial(TLS13RecordError)
}
