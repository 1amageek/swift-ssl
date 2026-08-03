import SSLCore

enum DTLSActionBatchCombiner {
  static func appending(
    _ suffix: consuming DTLSActionBatch,
    to prefix: consuming DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    if prefix.bytes.isEmpty {
      var actions = prefix.actions
      actions.append(contentsOf: suffix.actions)
      return try makeBatch(bytes: suffix.bytes, actions: actions)
    }
    if suffix.bytes.isEmpty {
      var actions = prefix.actions
      actions.append(contentsOf: suffix.actions)
      return try makeBatch(bytes: prefix.bytes, actions: actions)
    }

    var bytes = ContiguousArray<UInt8>()
    bytes.reserveCapacity(prefix.bytes.count + suffix.bytes.count)
    append(prefix.bytes.span, to: &bytes)
    let suffixOffset = bytes.count
    append(suffix.bytes.span, to: &bytes)
    var actions = prefix.actions
    for action in suffix.actions {
      actions.append(try shifted(action, by: suffixOffset))
    }
    return try makeBatch(
      bytes: OwnedBytes(consuming: bytes),
      actions: actions
    )
  }

  static func appending(
    _ actions: consuming ContiguousArray<DTLSAction>,
    to batch: consuming DTLSActionBatch
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    var combined = batch.actions
    combined.append(contentsOf: actions)
    return try makeBatch(bytes: batch.bytes, actions: combined)
  }

  static func empty() throws(DTLS13ConnectionError) -> DTLSActionBatch {
    try makeBatch(bytes: OwnedBytes(), actions: [])
  }

  private static func shifted(
    _ action: DTLSAction,
    by offset: Int
  ) throws(DTLS13ConnectionError) -> DTLSAction {
    switch action {
    case .emitDatagram(let range):
      return .emitDatagram(
        try shifted(range, by: offset)
      )
    case .deliverApplicationData(let range, let isEarlyData):
      return .deliverApplicationData(
        bytes: try shifted(range, by: offset),
        isEarlyData: isEarlyData
      )
    case .sendAlert(let alert): return .sendAlert(alert)
    case .handshakeComplete: return .handshakeComplete
    case .handshakeConfirmed: return .handshakeConfirmed
    case .flushFlight: return .flushFlight
    case .scheduleRetransmission(let delay):
      return .scheduleRetransmission(afterMilliseconds: delay)
    case .cancelRetransmission: return .cancelRetransmission
    }
  }

  private static func shifted(
    _ range: ByteRange,
    by offset: Int
  ) throws(DTLS13ConnectionError) -> ByteRange {
    let (shiftedOffset, overflow) = range.offset.addingReportingOverflow(offset)
    guard !overflow else {
      throw .output(.offsetOverflow(offset: range.offset, count: offset))
    }
    do {
      return try ByteRange(offset: shiftedOffset, count: range.count)
    } catch let error {
      throw .output(error)
    }
  }

  private static func makeBatch(
    bytes: consuming OwnedBytes,
    actions: consuming ContiguousArray<DTLSAction>
  ) throws(DTLS13ConnectionError) -> DTLSActionBatch {
    do {
      return try DTLSActionBatch(bytes: bytes, actions: actions)
    } catch let error {
      throw .output(error)
    }
  }

  private static func append(
    _ source: Span<UInt8>,
    to destination: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      destination.append(source[index])
      index += 1
    }
  }
}
