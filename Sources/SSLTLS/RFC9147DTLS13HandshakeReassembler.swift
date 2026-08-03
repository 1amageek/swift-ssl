import SSLCore

/// Bounded, order-preserving DTLS 1.3 handshake fragment reassembly.
///
/// Fragment bodies are copied because their source datagram borrow ends when
/// `receive` returns. The complete TLS-form handshake message is materialized
/// once, only when the next sequence is ready for the semantic TLS core.
public struct RFC9147DTLS13HandshakeReassembler: DTLS13HandshakeReassembling, Sendable {
  public static let defaultMaximumBufferedByteCount = 2 * 1024 * 1024
  public static let defaultMaximumBufferedMessageCount = 32

  public private(set) var nextReceiveSequence: UInt16
  public private(set) var bufferedByteCount: Int

  private let maximumBufferedByteCount: Int
  private let maximumBufferedMessageCount: Int
  private var messages: [UInt16: MessageState]
  private var isSequenceExhausted: Bool

  public init(
    maximumBufferedByteCount: Int = Self.defaultMaximumBufferedByteCount,
    maximumBufferedMessageCount: Int = Self.defaultMaximumBufferedMessageCount
  ) throws(DTLS13HandshakeFragmentError) {
    guard maximumBufferedByteCount >= 0 else {
      throw .bufferingLimitExceeded(limit: maximumBufferedByteCount, attempted: 0)
    }
    guard maximumBufferedMessageCount > 0 else {
      throw .bufferingLimitExceeded(limit: maximumBufferedMessageCount, attempted: 1)
    }
    self.maximumBufferedByteCount = maximumBufferedByteCount
    self.maximumBufferedMessageCount = maximumBufferedMessageCount
    nextReceiveSequence = 0
    bufferedByteCount = 0
    messages = [:]
    isSequenceExhausted = false
  }

  public mutating func receive(
    _ fragment: DTLS13HandshakeFragment,
    from recordContent: Span<UInt8>
  ) throws(DTLS13HandshakeFragmentError) {
    guard !isSequenceExhausted else { return }
    guard fragment.messageSequence >= nextReceiveSequence else { return }
    guard fragment.fragment.endOffset <= recordContent.count else {
      throw .byte(
        .outOfBounds(
          offset: fragment.fragment.offset,
          requested: fragment.fragment.count,
          available: Swift.max(0, recordContent.count - fragment.fragment.offset)
        )
      )
    }

    var state: MessageState
    if let existing = messages.removeValue(forKey: fragment.messageSequence) {
      guard existing.messageType == fragment.messageType,
        existing.body.count == fragment.messageByteCount
      else {
        messages[fragment.messageSequence] = existing
        throw .conflictingMessageMetadata(sequence: fragment.messageSequence)
      }
      state = existing
    } else {
      guard messages.count < maximumBufferedMessageCount else {
        throw .bufferingLimitExceeded(
          limit: maximumBufferedMessageCount,
          attempted: messages.count + 1
        )
      }
      let (attempted, overflow) = bufferedByteCount.addingReportingOverflow(
        fragment.messageByteCount
      )
      guard !overflow, attempted <= maximumBufferedByteCount else {
        throw .bufferingLimitExceeded(
          limit: maximumBufferedByteCount,
          attempted: overflow ? Int.max : attempted
        )
      }
      state = MessageState(
        messageType: fragment.messageType,
        bodyByteCount: fragment.messageByteCount
      )
      bufferedByteCount = attempted
    }

    let fragmentBytes = recordContent.extracting(
      fragment.fragment.offset..<fragment.fragment.endOffset
    )
    do {
      try state.insert(
        fragmentBytes,
        at: fragment.fragmentOffset,
        messageSequence: fragment.messageSequence
      )
      messages[fragment.messageSequence] = state
    } catch {
      messages[fragment.messageSequence] = state
      throw error
    }
  }

  public mutating func takeNextMessage() -> OwnedBytes? {
    guard let state = messages[nextReceiveSequence], state.isComplete else {
      return nil
    }
    messages.removeValue(forKey: nextReceiveSequence)
    bufferedByteCount -= state.body.count
    if nextReceiveSequence == UInt16.max {
      isSequenceExhausted = true
    } else {
      nextReceiveSequence &+= 1
    }

    var message = ContiguousArray<UInt8>()
    message.reserveCapacity(4 + state.body.count)
    message.append(state.messageType)
    message.append(UInt8(truncatingIfNeeded: state.body.count >> 16))
    message.append(UInt8(truncatingIfNeeded: state.body.count >> 8))
    message.append(UInt8(truncatingIfNeeded: state.body.count))
    message.append(contentsOf: state.body)
    return OwnedBytes(consuming: message)
  }

  private struct MessageState: Sendable {
    let messageType: UInt8
    var body: ContiguousArray<UInt8>
    var received: ContiguousArray<UInt8>
    var receivedByteCount: Int

    init(messageType: UInt8, bodyByteCount: Int) {
      self.messageType = messageType
      body = ContiguousArray(repeating: 0, count: bodyByteCount)
      received = ContiguousArray(repeating: 0, count: bodyByteCount)
      receivedByteCount = 0
    }

    var isComplete: Bool { receivedByteCount == body.count }

    mutating func insert(
      _ fragment: Span<UInt8>,
      at offset: Int,
      messageSequence: UInt16
    ) throws(DTLS13HandshakeFragmentError) {
      var index = 0
      while index < fragment.count {
        let destinationIndex = offset + index
        if received[destinationIndex] == 0 {
          body[destinationIndex] = fragment[index]
          received[destinationIndex] = 1
          receivedByteCount += 1
        } else if body[destinationIndex] != fragment[index] {
          throw .conflictingOverlap(
            sequence: messageSequence,
            offset: destinationIndex
          )
        }
        index += 1
      }
    }
  }
}
