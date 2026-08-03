import SSLCore

public struct RFC9147DTLS13HandshakeFragmentCodec: DTLS13HandshakeFragmentCoding, Sendable {
  public static let headerByteCount = 12
  public static let maximumProtocolMessageByteCount = 0x00FF_FFFF

  public let maximumMessageByteCount: Int

  public init(
    maximumMessageByteCount: Int = TLS13HandshakeMessageFramer.defaultMaximumMessageByteCount
  ) throws(DTLS13HandshakeFragmentError) {
    let maximumBodyByteCount = Self.maximumProtocolMessageByteCount
    guard maximumMessageByteCount >= 4,
      maximumMessageByteCount - 4 <= maximumBodyByteCount
    else {
      throw .messageTooLarge(
        maximum: maximumBodyByteCount + 4,
        actual: maximumMessageByteCount
      )
    }
    self.maximumMessageByteCount = maximumMessageByteCount
  }

  public func fragments(
    in recordContent: Span<UInt8>
  ) throws(DTLS13HandshakeFragmentError) -> ContiguousArray<DTLS13HandshakeFragment> {
    var cursor = ByteCursor(recordContent)
    var fragments = ContiguousArray<DTLS13HandshakeFragment>()
    do {
      while !cursor.isAtEnd {
        let messageType = try cursor.readByte()
        let messageByteCount = Int(try cursor.readUInt24BigEndian())
        let messageSequence = try cursor.readUInt16BigEndian()
        let fragmentOffset = Int(try cursor.readUInt24BigEndian())
        let fragmentByteCount = Int(try cursor.readUInt24BigEndian())
        try validate(
          messageByteCount: messageByteCount,
          fragmentOffset: fragmentOffset,
          fragmentByteCount: fragmentByteCount
        )
        let bodyOffset = cursor.offset
        _ = try cursor.readSpan(count: fragmentByteCount)
        fragments.append(
          DTLS13HandshakeFragment(
            messageType: messageType,
            messageByteCount: messageByteCount,
            messageSequence: messageSequence,
            fragmentOffset: fragmentOffset,
            fragment: try ByteRange(offset: bodyOffset, count: fragmentByteCount)
          )
        )
      }
    } catch let error as DTLS13HandshakeFragmentError {
      throw error
    } catch let error as ByteError {
      throw .byte(error)
    } catch {
      throw .malformedFragment
    }
    return fragments
  }

  public func appendFragment(
    tlsHandshakeMessage: Span<UInt8>,
    messageSequence: UInt16,
    fragmentOffset: Int,
    fragmentByteCount: Int,
    to output: inout ContiguousArray<UInt8>
  ) throws(DTLS13HandshakeFragmentError) {
    guard tlsHandshakeMessage.count >= 4 else { throw .malformedFragment }
    let messageByteCount =
      (Int(tlsHandshakeMessage[1]) << 16)
      | (Int(tlsHandshakeMessage[2]) << 8)
      | Int(tlsHandshakeMessage[3])
    guard tlsHandshakeMessage.count == messageByteCount + 4 else {
      throw .malformedFragment
    }
    try validate(
      messageByteCount: messageByteCount,
      fragmentOffset: fragmentOffset,
      fragmentByteCount: fragmentByteCount
    )
    output.reserveCapacity(output.count + Self.headerByteCount + fragmentByteCount)
    output.append(tlsHandshakeMessage[0])
    Self.appendUInt24(messageByteCount, to: &output)
    output.append(UInt8(truncatingIfNeeded: messageSequence >> 8))
    output.append(UInt8(truncatingIfNeeded: messageSequence))
    Self.appendUInt24(fragmentOffset, to: &output)
    Self.appendUInt24(fragmentByteCount, to: &output)
    var index = 0
    while index < fragmentByteCount {
      output.append(tlsHandshakeMessage[4 + fragmentOffset + index])
      index += 1
    }
  }

  private func validate(
    messageByteCount: Int,
    fragmentOffset: Int,
    fragmentByteCount: Int
  ) throws(DTLS13HandshakeFragmentError) {
    guard messageByteCount + 4 <= maximumMessageByteCount else {
      throw .messageTooLarge(
        maximum: maximumMessageByteCount,
        actual: messageByteCount + 4
      )
    }
    guard fragmentByteCount > 0 || messageByteCount == 0 else {
      throw .emptyFragmentForNonemptyMessage
    }
    let (endOffset, overflow) = fragmentOffset.addingReportingOverflow(fragmentByteCount)
    guard !overflow, fragmentOffset >= 0, fragmentByteCount >= 0,
      endOffset <= messageByteCount
    else {
      throw .fragmentOutsideMessage(
        offset: fragmentOffset,
        count: fragmentByteCount,
        messageByteCount: messageByteCount
      )
    }
  }

  private static func appendUInt24(
    _ value: Int,
    to output: inout ContiguousArray<UInt8>
  ) {
    output.append(UInt8(truncatingIfNeeded: value >> 16))
    output.append(UInt8(truncatingIfNeeded: value >> 8))
    output.append(UInt8(truncatingIfNeeded: value))
  }
}
