import SwiftSSLCore

public enum DTLS13HandshakeFragmentError: Error, Sendable, Equatable {
  case byte(ByteError)
  case malformedFragment
  case messageTooLarge(maximum: Int, actual: Int)
  case emptyFragmentForNonemptyMessage
  case fragmentOutsideMessage(offset: Int, count: Int, messageByteCount: Int)
  case messageSequenceExhausted
  case unexpectedMessageSequence(expected: UInt16, actual: UInt16)
  case conflictingMessageMetadata(sequence: UInt16)
  case conflictingOverlap(sequence: UInt16, offset: Int)
  case bufferingLimitExceeded(limit: Int, attempted: Int)
}
