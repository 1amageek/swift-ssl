import SSLCore
import SSLCrypto
import SSLX509

enum TLS13HandshakeWire {
  static let handshakeContentType: UInt8 = TLS13ContentType.handshake.rawValue
  static let maximumInputByteCount = 4 * 16_384

  static func recordRanges(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ContiguousArray<ByteRange> {
    guard input.count <= maximumInputByteCount else { throw .malformedInput }
    var cursor = ByteCursor(input)
    var result = ContiguousArray<ByteRange>()
    do {
      while !cursor.isAtEnd {
        guard cursor.remainingCount >= TLS13RecordProtector.recordHeaderByteCount else {
          throw ByteError.outOfBounds(
            offset: cursor.offset,
            requested: TLS13RecordProtector.recordHeaderByteCount,
            available: cursor.remainingCount
          )
        }
        let start = cursor.offset
        let type = try cursor.readByte()
        guard
          type == TLS13ContentType.handshake.rawValue
            || type == TLS13ContentType.applicationData.rawValue
        else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        guard try cursor.readByte() == 0x03,
          try cursor.readByte() == 0x03
        else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        let length = Int(try cursor.readUInt16BigEndian())
        guard length <= TLS13RecordProtector.maximumCiphertextByteCount,
          length <= cursor.remainingCount
        else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        _ = try cursor.readSpan(count: length)
        result.append(
          try ByteRange(offset: start, count: cursor.offset - start)
        )
      }
    } catch let error as TLS13HandshakeEngineError {
      throw error
    } catch {
      throw .malformedInput
    }
    return result
  }

  static func handshakeMessageRanges(
    _ input: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> ContiguousArray<ByteRange> {
    var result = ContiguousArray<ByteRange>()
    var offset = 0
    do {
      while offset < input.count {
        guard input.count - offset >= TLS13HandshakeMessageFramer.headerByteCount else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        let bodyByteCount =
          (Int(input[offset + 1]) << 16)
          | (Int(input[offset + 2]) << 8)
          | Int(input[offset + 3])
        let messageByteCount = TLS13HandshakeMessageFramer.headerByteCount + bodyByteCount
        guard messageByteCount <= input.count - offset else {
          throw TLS13HandshakeEngineError.malformedInput
        }
        result.append(
          try ByteRange(offset: offset, count: messageByteCount)
        )
        offset += messageByteCount
      }
    } catch let error as TLS13HandshakeEngineError {
      throw error
    } catch let error as ByteError {
      throw .output(error)
    } catch {
      throw .malformedInput
    }
    guard !result.isEmpty else { throw .malformedInput }
    return result
  }

  static func plaintextPayload(
    record: Span<UInt8>
  ) throws(TLS13HandshakeEngineError) -> Span<UInt8> {
    guard record.count >= TLS13RecordProtector.recordHeaderByteCount,
      record[0] == handshakeContentType
    else {
      throw .malformedInput
    }
    return record.extracting(
      TLS13RecordProtector.recordHeaderByteCount..<record.count
    )
  }

  static func appendPlaintextRecord(
    _ message: Span<UInt8>,
    to output: inout ContiguousArray<UInt8>
  ) throws(TLS13HandshakeEngineError) {
    guard message.count <= TLS13RecordProtector.maximumPlaintextByteCount else {
      throw .record(.invalidContentLength(actual: message.count))
    }
    output.reserveCapacity(
      output.count + TLS13RecordProtector.recordHeaderByteCount + message.count)
    output.append(handshakeContentType)
    output.append(0x03)
    output.append(0x03)
    output.append(UInt8(truncatingIfNeeded: message.count >> 8))
    output.append(UInt8(truncatingIfNeeded: message.count))
    append(message, to: &output)
  }

  static func appendSealedRecord(
    content: Span<UInt8>,
    contentType: TLS13ContentType,
    with protector: inout TLS13RecordProtector,
    to output: inout ContiguousArray<UInt8>
  ) throws(TLS13HandshakeEngineError) {
    guard content.count <= TLS13RecordProtector.maximumPlaintextByteCount else {
      throw .record(.invalidContentLength(actual: content.count))
    }
    let recordByteCount = TLS13RecordProtector.recordHeaderByteCount + content.count + 1 + 16
    let start = output.count
    guard start <= Int.max - recordByteCount else { throw .malformedInput }
    output.append(contentsOf: repeatElement(0, count: recordByteCount))
    do {
      try output.withUnsafeMutableBufferPointer { buffer throws(TLS13RecordError) in
        // Unsafe boundary invariants:
        // - output owns initialized UInt8 storage for start..<start + recordByteCount.
        // - The checked content limit makes recordByteCount positive and prevents
        //   arithmetic overflow; UInt8 has alignment and stride one.
        // - Memory remains bound to UInt8 and is exclusively mutated here.
        // - content belongs to the core output or caller and cannot alias output.
        // - The pointer is borrowed only for this synchronous closure and no
        //   pointer, span, or owner crosses a Sendable boundary.
        let baseAddress = buffer.baseAddress!.advanced(by: start)
        var destination = MutableSpan(
          _unsafeStart: baseAddress,
          count: recordByteCount
        )
        try protector.seal(
          content: content,
          contentType: contentType,
          into: &destination
        )
      }
    } catch let error {
      output.removeLast(recordByteCount)
      throw .record(error)
    }
  }

  static func seal(
    content: Span<UInt8>,
    contentType: TLS13ContentType,
    with protector: inout TLS13RecordProtector
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    var output = ContiguousArray<UInt8>()
    try appendSealedRecord(
      content: content,
      contentType: contentType,
      with: &protector,
      to: &output
    )
    return OwnedBytes(consuming: output)
  }

  static func open(
    record: Span<UInt8>,
    expectedContentType: TLS13ContentType = .handshake,
    with protector: inout TLS13RecordProtector
  ) throws(TLS13HandshakeEngineError) -> OwnedBytes {
    let innerByteCount = Swift.max(
      0,
      record.count - TLS13RecordProtector.recordHeaderByteCount - 16
    )
    var plaintext = ContiguousArray<UInt8>(repeating: 0, count: innerByteCount)
    var destination = plaintext.mutableSpan
    let contentType: TLS13ContentType
    do {
      contentType = try protector.open(record: record, into: &destination)
    } catch let error {
      throw .record(error)
    }
    guard contentType == expectedContentType else { throw .malformedInput }
    let unusedByteCount = plaintext.count - protector.lastOpenedByteCount
    if unusedByteCount > 0 {
      plaintext.removeLast(unusedByteCount)
    }
    return OwnedBytes(consuming: plaintext)
  }

  static func makeOutput(
    bytes: consuming OwnedBytes,
    terminalActions: consuming ContiguousArray<TLSStreamAction> = []
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    var actions = ContiguousArray<TLSStreamAction>()
    if !bytes.isEmpty {
      do {
        actions.append(
          .emitRecordBytes(try ByteRange(offset: 0, count: bytes.count))
        )
      } catch let error {
        throw .output(error)
      }
    }
    actions.append(contentsOf: terminalActions)
    return try TLS13HandshakeOutput(bytes: bytes, actions: actions)
  }

  static func makeOutput(
    storage: consuming ContiguousArray<UInt8>,
    terminalActions: consuming ContiguousArray<TLSStreamAction> = []
  ) throws(TLS13HandshakeEngineError) -> TLS13HandshakeOutput {
    try makeOutput(
      bytes: OwnedBytes(consuming: storage),
      terminalActions: terminalActions
    )
  }

  static func certificateVerifyInput(
    role: TLSRole,
    transcriptHash: Span<UInt8>
  ) -> OwnedBytes {
    var bytes = ContiguousArray<UInt8>(repeating: 0x20, count: 64)
    switch role {
    case .client:
      bytes.append(contentsOf: "TLS 1.3, client CertificateVerify".utf8)
    case .server:
      bytes.append(contentsOf: "TLS 1.3, server CertificateVerify".utf8)
    }
    bytes.append(0)
    append(transcriptHash, to: &bytes)
    return OwnedBytes(consuming: bytes)
  }

  private static func append(
    _ source: Span<UInt8>,
    to target: inout ContiguousArray<UInt8>
  ) {
    var index = 0
    while index < source.count {
      target.append(source[index])
      index += 1
    }
  }
}

func mapHandshakeEngineError(_ error: any Error) -> TLS13HandshakeEngineError {
  if let error = error as? TLS13HandshakeEngineError { return error }
  if let error = error as? TLS13HandshakeError { return .handshake(error) }
  if let error = error as? TLS13RecordError { return .record(error) }
  if let error = error as? TLS13KeyScheduleError { return .keySchedule(error) }
  if let error = error as? TLS13KeyExchangeError { return .keyExchange(error) }
  if let error = error as? CryptoInputError { return .crypto(error) }
  if let error = error as? TLS13SigningError { return .signing(error) }
  if let error = error as? X25519KeyGenerationError { return .x25519(error) }
  if let error = error as? X509CertificateError { return .certificate(error) }
  if let error = error as? TLS13ServerCertificateValidationError {
    return .certificateValidation(error)
  }
  if let error = error as? TLS13SessionTicketError { return .sessionTicket(error) }
  if let error = error as? TLS13ResumptionError { return .resumption(error) }
  if let error = error as? TLS13PSKError { return .preSharedKey(error) }
  if let error = error as? TLS13CertificateCompressionError {
    return .certificateCompression(error)
  }
  if let error = error as? TLS13DelegatedCredentialError {
    return .delegatedCredential(error)
  }
  if let error = error as? ECHError { return .ech(error) }
  if let error = error as? ByteError { return .output(error) }
  return .malformedInput
}

func expectedObfuscatedTicketAge(
  at instant: VerificationInstant,
  issuedAt: VerificationInstant,
  lifetime: UInt32,
  ageAdd: UInt32
) -> UInt32? {
  guard instant >= issuedAt else { return nil }
  let seconds = instant.secondsSinceUnixEpoch.subtractingReportingOverflow(
    issuedAt.secondsSinceUnixEpoch
  )
  guard !seconds.overflow, seconds.partialValue >= 0 else { return nil }
  let milliseconds = seconds.partialValue.multipliedReportingOverflow(by: 1_000)
  guard !milliseconds.overflow else { return nil }
  let nanoseconds = Int64(instant.nanoseconds) - Int64(issuedAt.nanoseconds)
  let adjusted =
    nanoseconds < 0
    ? milliseconds.partialValue - 1
    : milliseconds.partialValue
  guard adjusted >= 0 else { return nil }
  let lifetimeMilliseconds = UInt64(lifetime) * 1_000
  guard UInt64(adjusted) <= lifetimeMilliseconds else { return nil }
  return UInt32(truncatingIfNeeded: UInt64(adjusted) &+ UInt64(ageAdd))
}

func ticketAgeWithinTolerance(
  offered: UInt32,
  expected: UInt32,
  toleranceMilliseconds: UInt32
) -> Bool {
  let forward = offered &- expected
  let backward = expected &- offered
  return min(forward, backward) <= toleranceMilliseconds
}

func engineTry<Result: ~Copyable>(
  _ body: () throws -> Result
) throws(TLS13HandshakeEngineError) -> Result {
  do {
    return try body()
  } catch let error {
    throw mapHandshakeEngineError(error)
  }
}

func makeCertificateVerifyMessage(
  signatureScheme: TLS13SignatureScheme,
  signature: consuming ContiguousArray<UInt8>
) throws(TLS13HandshakeEngineError) -> OwnedBytes {
  let owner = OwnedBytes(consuming: signature)
  do {
    return try TLS13HandshakeCodec.makeCertificateVerify(
      signatureScheme: signatureScheme,
      signature: owner.span
    )
  } catch let error {
    throw mapHandshakeEngineError(error)
  }
}

func wipe(_ bytes: inout ContiguousArray<UInt8>) {
  bytes.withUnsafeMutableBufferPointer { buffer in
    guard let baseAddress = buffer.baseAddress else { return }
    SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
  }
}
