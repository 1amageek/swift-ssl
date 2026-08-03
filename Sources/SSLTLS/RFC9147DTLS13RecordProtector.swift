import SSLCore
import SSLCrypto

/// RFC 9147 DTLSCiphertext protection for one direction and epoch.
///
/// The owner keeps traffic key material, record-number key material, sequence
/// state, and the receive replay window together. Pointer access is delegated
/// to the scoped, in-place AEAD boundary used by `TLS13RecordProtector`.
public struct RFC9147DTLS13RecordProtector: DTLS13RecordProtecting, ~Copyable, Sendable {
  public static let maximumPlaintextByteCount = 16_384
  public static let maximumPaddingByteCount = 255
  public static let maximumCiphertextByteCount = 16_640
  static let maximumSendingEpoch: UInt64 = (1 << 48) - 1

  public let cipherSuite: TLSCipherSuite
  public let epoch: UInt64

  private let key: SecretBytes
  private let iv: SecretBytes
  private let sequenceNumberKey: SecretBytes
  private let connectionID: OwnedBytes
  private var sequenceNumber: UInt64
  private var replayWindow: DTLS13ReplayWindow
  public private(set) var lastOpenedRecordNumber: DTLS13RecordNumber?
  public private(set) var lastOpenedByteCount: Int

  public init(
    cipherSuite: TLSCipherSuite,
    trafficSecret: Span<UInt8>,
    epoch: UInt64,
    connectionID: Span<UInt8>? = nil
  ) throws(DTLS13RecordError) {
    guard epoch > 0 else { throw .invalidEpoch(epoch) }
    let hashByteCount = TLS13RecordProtector.hashByteCount(for: cipherSuite)
    guard trafficSecret.count == hashByteCount else {
      throw .keyMaterial(
        .invalidTrafficSecretLength(
          expected: hashByteCount,
          actual: trafficSecret.count
        )
      )
    }
    let keyByteCount = TLS13RecordProtector.keyByteCount(for: cipherSuite)
    guard (connectionID?.count ?? 0) <= UInt8.max else {
      throw .recordTooLarge(limit: Int(UInt8.max), actual: connectionID?.count ?? 0)
    }
    let derivedKey = try Self.deriveSecret(
      trafficSecret: trafficSecret,
      label: "key",
      outputByteCount: keyByteCount,
      cipherSuite: cipherSuite
    )
    let derivedIV = try Self.deriveSecret(
      trafficSecret: trafficSecret,
      label: "iv",
      outputByteCount: 12,
      cipherSuite: cipherSuite
    )
    let derivedSequenceNumberKey = try Self.deriveSecret(
      trafficSecret: trafficSecret,
      label: "sn",
      outputByteCount: keyByteCount,
      cipherSuite: cipherSuite
    )
    key = derivedKey
    iv = derivedIV
    sequenceNumberKey = derivedSequenceNumberKey
    if let connectionID {
      self.connectionID = OwnedBytes(copying: connectionID)
    } else {
      self.connectionID = OwnedBytes()
    }
    self.cipherSuite = cipherSuite
    self.epoch = epoch
    sequenceNumber = 0
    replayWindow = DTLS13ReplayWindow()
    lastOpenedRecordNumber = nil
    lastOpenedByteCount = 0
  }

  public var currentSequenceNumber: UInt64 { sequenceNumber }

  public func sealedRecordByteCount(
    contentByteCount: Int,
    paddingByteCount: Int = 0
  ) throws(DTLS13RecordError) -> Int {
    try Self.validateContent(
      contentByteCount,
      paddingByteCount: paddingByteCount
    )
    return headerByteCount(sequenceByteCount: 2, includesLength: true)
      + contentByteCount + 1 + paddingByteCount + TLS13RecordProtector.tagByteCount
  }

  public mutating func seal(
    content: Span<UInt8>,
    contentType: DTLS13RecordContentType,
    paddingByteCount: Int = 0,
    into output: inout MutableSpan<UInt8>
  ) throws(DTLS13RecordError) -> DTLS13RecordNumber {
    try Self.validateContent(content.count, paddingByteCount: paddingByteCount)
    guard sequenceNumber <= DTLS13ReplayWindow.maximumSequenceNumber else {
      throw .invalidSequenceNumber(sequenceNumber)
    }
    let headerByteCount = headerByteCount(sequenceByteCount: 2, includesLength: true)
    let innerByteCount = content.count + 1 + paddingByteCount
    let ciphertextByteCount = innerByteCount + TLS13RecordProtector.tagByteCount
    let recordByteCount = headerByteCount + ciphertextByteCount
    guard output.count >= recordByteCount else {
      throw .outputTooSmall(required: recordByteCount, actual: output.count)
    }
    guard !TLS13RecordProtector.spansOverlap(content, output.span) else {
      throw .overlappingInputAndOutput
    }
    let recordNumber = try DTLS13RecordNumber(
      epoch: epoch,
      sequenceNumber: sequenceNumber
    )
    var unmaskedHeader = makeHeader(
      sequenceNumber: sequenceNumber,
      sequenceByteCount: 2,
      ciphertextByteCount: ciphertextByteCount,
      includesLength: true
    )
    var nonce = TLS13RecordProtector.makeNonce(
      iv: iv,
      sequenceNumber: sequenceNumber
    )
    defer {
      TLS13RecordProtector.wipe(&nonce)
      TLS13RecordProtector.wipe(&unmaskedHeader)
    }

    var sealSucceeded = false
    output.withUnsafeMutableBytes { rawBytes in
      guard let rawBaseAddress = rawBytes.baseAddress else { return }
      let baseAddress = rawBaseAddress.assumingMemoryBound(to: UInt8.self)
      var index = 0
      while index < unmaskedHeader.count {
        baseAddress[index] = unmaskedHeader[index]
        index += 1
      }
      index = 0
      while index < content.count {
        baseAddress[headerByteCount + index] = content[index]
        index += 1
      }
      baseAddress[headerByteCount + content.count] = contentType.rawValue
      index = 0
      while index < paddingByteCount {
        baseAddress[headerByteCount + content.count + 1 + index] = 0
        index += 1
      }
      let plaintext = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: baseAddress.advanced(by: headerByteCount),
          count: innerByteCount
        )
      )
      var sealed = MutableSpan(
        _unsafeStart: baseAddress.advanced(by: headerByteCount),
        count: ciphertextByteCount
      )
      key.withBorrowedBytes { keyBytes in
        sealSucceeded = TLS13RecordProtector.withCipher(
          cipherSuite: cipherSuite,
          key: keyBytes,
          plaintext: plaintext,
          authenticatedData: unmaskedHeader.span,
          nonce: nonce.span,
          into: &sealed
        )
      }
      guard sealSucceeded else { return }
      let sample = Span(
        _unsafeElements: UnsafeBufferPointer(
          start: baseAddress.advanced(by: headerByteCount),
          count: 16
        )
      )
      if let mask = try? makeRecordNumberMask(sample: sample) {
        let sequenceOffset = 1 + connectionID.count
        baseAddress[sequenceOffset] ^= mask[0]
        baseAddress[sequenceOffset + 1] ^= mask[1]
      } else {
        sealSucceeded = false
      }
    }
    guard sealSucceeded else { throw .authenticationFailed }
    sequenceNumber &+= 1
    return recordNumber
  }

  public mutating func open(
    record: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(DTLS13RecordError) -> DTLS13RecordContentType {
    lastOpenedByteCount = 0
    lastOpenedRecordNumber = nil
    guard record.count >= 1 + connectionID.count + 1 + 16 else {
      throw .malformedRecord
    }
    let firstByte = record[0]
    guard firstByte & 0xE0 == 0x20 else { throw .malformedRecord }
    let hasConnectionID = firstByte & 0x10 != 0
    guard hasConnectionID == !connectionID.isEmpty else {
      throw .connectionIDMismatch
    }
    guard UInt64(firstByte & 0x03) == epoch & 0x03 else {
      throw .invalidEpoch(UInt64(firstByte & 0x03))
    }
    var cursor = 1
    if hasConnectionID {
      guard record.count >= cursor + connectionID.count else {
        throw .malformedRecord
      }
      var index = 0
      while index < connectionID.count {
        guard record[cursor + index] == connectionID[index] else {
          throw .connectionIDMismatch
        }
        index += 1
      }
      cursor += connectionID.count
    }
    let sequenceByteCount = firstByte & 0x08 == 0 ? 1 : 2
    let sequenceOffset = cursor
    cursor += sequenceByteCount
    let includesLength = firstByte & 0x04 != 0
    let headerByteCount: Int
    let ciphertextByteCount: Int
    if includesLength {
      guard record.count >= cursor + 2 else { throw .malformedRecord }
      ciphertextByteCount = (Int(record[cursor]) << 8) | Int(record[cursor + 1])
      cursor += 2
      headerByteCount = cursor
      guard ciphertextByteCount == record.count - headerByteCount else {
        throw .malformedRecord
      }
    } else {
      headerByteCount = cursor
      ciphertextByteCount = record.count - headerByteCount
    }
    guard ciphertextByteCount >= 16,
      ciphertextByteCount <= Self.maximumCiphertextByteCount
    else {
      throw .recordTooLarge(
        limit: Self.maximumCiphertextByteCount,
        actual: ciphertextByteCount
      )
    }

    let ciphertext = record.extracting(headerByteCount..<record.count)
    let sample = ciphertext.extracting(0..<16)
    var unmaskedHeader = ContiguousArray<UInt8>()
    unmaskedHeader.reserveCapacity(headerByteCount)
    var index = 0
    while index < headerByteCount {
      unmaskedHeader.append(record[index])
      index += 1
    }
    let mask = try makeRecordNumberMask(sample: sample)
    index = 0
    while index < sequenceByteCount {
      unmaskedHeader[sequenceOffset + index] ^= mask[index]
      index += 1
    }
    var truncatedSequenceNumber: UInt64 = 0
    index = 0
    while index < sequenceByteCount {
      truncatedSequenceNumber =
        (truncatedSequenceNumber << 8)
        | UInt64(unmaskedHeader[sequenceOffset + index])
      index += 1
    }
    let fullSequenceNumber = try RFC9147DTLS13SequenceNumberReconstructor().reconstruct(
      truncatedSequenceNumber: truncatedSequenceNumber,
      bitCount: sequenceByteCount * 8,
      highestAuthenticatedSequenceNumber: replayWindow.largestReceived
    )
    let recordNumber = try DTLS13RecordNumber(
      epoch: epoch,
      sequenceNumber: fullSequenceNumber
    )
    let wasAlreadyReceived: Bool
    do {
      wasAlreadyReceived = try replayWindow.contains(fullSequenceNumber)
    } catch let error {
      throw .replay(error)
    }
    if wasAlreadyReceived {
      throw .replayed(recordNumber)
    }
    let innerByteCount = ciphertextByteCount - TLS13RecordProtector.tagByteCount
    guard innerByteCount > 0 else { throw .malformedRecord }
    defer { TLS13RecordProtector.wipe(&unmaskedHeader) }
    var nonce = TLS13RecordProtector.makeNonce(
      iv: iv,
      sequenceNumber: fullSequenceNumber
    )
    defer { TLS13RecordProtector.wipe(&nonce) }
    let opensDirectlyIntoOutput = output.count >= innerByteCount
    var scratch = opensDirectlyIntoOutput
      ? ContiguousArray<UInt8>()
      : ContiguousArray<UInt8>(repeating: 0, count: innerByteCount)
    defer { TLS13RecordProtector.wipe(&scratch) }
    var openSucceeded = false
    if opensDirectlyIntoOutput {
      output.withUnsafeMutableBytes { rawBytes in
        // Unsafe boundary invariants:
        // - The caller exclusively owns an initialized output span of at least
        //   `innerByteCount`, selected by `opensDirectlyIntoOutput`.
        // - The pointer is borrowed only by this synchronous closure.
        // - UInt8 has unit stride/alignment and no pointer escapes.
        let baseAddress = rawBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
        var destination = MutableSpan(_unsafeStart: baseAddress, count: innerByteCount)
        key.withBorrowedBytes { keyBytes in
          openSucceeded = TLS13RecordProtector.withCipherOpen(
            cipherSuite: cipherSuite,
            key: keyBytes,
            ciphertextAndTag: ciphertext,
            authenticatedData: unmaskedHeader.span,
            nonce: nonce.span,
            into: &destination
          )
        }
      }
    } else {
      scratch.withUnsafeMutableBufferPointer { buffer in
        var destination = MutableSpan(
          _unsafeStart: buffer.baseAddress!,
          count: innerByteCount
        )
        key.withBorrowedBytes { keyBytes in
          openSucceeded = TLS13RecordProtector.withCipherOpen(
            cipherSuite: cipherSuite,
            key: keyBytes,
            ciphertextAndTag: ciphertext,
            authenticatedData: unmaskedHeader.span,
            nonce: nonce.span,
            into: &destination
          )
        }
      }
    }
    guard openSucceeded else { throw .authenticationFailed }

    var contentTypeIndex = innerByteCount - 1
    if opensDirectlyIntoOutput {
      while contentTypeIndex >= 0, output[contentTypeIndex] == 0 {
        contentTypeIndex -= 1
      }
    } else {
      while contentTypeIndex >= 0, scratch[contentTypeIndex] == 0 {
        contentTypeIndex -= 1
      }
    }
    let rawContentType = contentTypeIndex >= 0
      ? (opensDirectlyIntoOutput ? output[contentTypeIndex] : scratch[contentTypeIndex])
      : 0
    guard contentTypeIndex >= 0,
      let contentType = DTLS13RecordContentType(rawValue: rawContentType)
    else {
      throw .malformedRecord
    }
    guard output.count >= contentTypeIndex else {
      throw .outputTooSmall(required: contentTypeIndex, actual: output.count)
    }
    let replayDecision: DTLS13ReplayDecision
    do {
      replayDecision = try replayWindow.accept(fullSequenceNumber)
    } catch let error {
      throw .replay(error)
    }
    switch replayDecision {
    case .accepted:
      break
    case .replayed:
      throw .replayed(recordNumber)
    case .tooOld:
      throw .tooOld(recordNumber)
    }
    if opensDirectlyIntoOutput {
      index = contentTypeIndex
      while index < innerByteCount {
        output[index] = 0
        index += 1
      }
    } else {
      index = 0
      while index < contentTypeIndex {
        output[index] = scratch[index]
        index += 1
      }
    }
    lastOpenedByteCount = contentTypeIndex
    lastOpenedRecordNumber = recordNumber
    return contentType
  }

  private func headerByteCount(
    sequenceByteCount: Int,
    includesLength: Bool
  ) -> Int {
    1 + connectionID.count + sequenceByteCount + (includesLength ? 2 : 0)
  }

  private func makeHeader(
    sequenceNumber: UInt64,
    sequenceByteCount: Int,
    ciphertextByteCount: Int,
    includesLength: Bool
  ) -> ContiguousArray<UInt8> {
    var header = ContiguousArray<UInt8>()
    header.reserveCapacity(
      headerByteCount(
        sequenceByteCount: sequenceByteCount,
        includesLength: includesLength
      )
    )
    var firstByte: UInt8 = 0x20 | UInt8(truncatingIfNeeded: epoch & 0x03)
    if !connectionID.isEmpty { firstByte |= 0x10 }
    if sequenceByteCount == 2 { firstByte |= 0x08 }
    if includesLength { firstByte |= 0x04 }
    header.append(firstByte)
    var index = 0
    while index < connectionID.count {
      header.append(connectionID[index])
      index += 1
    }
    if sequenceByteCount == 2 {
      header.append(UInt8(truncatingIfNeeded: sequenceNumber >> 8))
    }
    header.append(UInt8(truncatingIfNeeded: sequenceNumber))
    if includesLength {
      header.append(UInt8(truncatingIfNeeded: ciphertextByteCount >> 8))
      header.append(UInt8(truncatingIfNeeded: ciphertextByteCount))
    }
    return header
  }

  private func makeRecordNumberMask(
    sample: Span<UInt8>
  ) throws(DTLS13RecordError) -> ContiguousArray<UInt8> {
    do {
      return try sequenceNumberKey.withBorrowedBytes { keyBytes throws(AEADError) in
        switch cipherSuite {
        case .aes128GCM_SHA256, .aes256GCM_SHA384:
          return try DTLSRecordNumberMask.aes(key: keyBytes, sample: sample)
        case .chacha20Poly1305_SHA256:
          return try ChaCha20Poly1305.recordNumberMask(
            key: keyBytes,
            sample: sample
          )
        }
      }
    } catch {
      throw .authenticationFailed
    }
  }

  private static func validateContent(
    _ contentByteCount: Int,
    paddingByteCount: Int
  ) throws(DTLS13RecordError) {
    guard contentByteCount >= 0,
      contentByteCount <= Self.maximumPlaintextByteCount
    else {
      throw .recordTooLarge(
        limit: Self.maximumPlaintextByteCount,
        actual: contentByteCount
      )
    }
    guard paddingByteCount >= 0,
      paddingByteCount <= Self.maximumPaddingByteCount
    else {
      throw .recordTooLarge(
        limit: Self.maximumPaddingByteCount,
        actual: paddingByteCount
      )
    }
  }

  private static func deriveSecret(
    trafficSecret: Span<UInt8>,
    label: String,
    outputByteCount: Int,
    cipherSuite: TLSCipherSuite
  ) throws(DTLS13RecordError) -> SecretBytes {
    do {
      return try TLS13RecordProtector.deriveSecret(
        trafficSecret: trafficSecret,
        label: label,
        outputByteCount: outputByteCount,
        cipherSuite: cipherSuite
      )
    } catch let error {
      throw .keyMaterial(error)
    }
  }
}
