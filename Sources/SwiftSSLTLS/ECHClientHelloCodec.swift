import SwiftSSLCore

/// RFC 9849 ClientHello encoding, AAD construction, and inner reconstruction.
public enum ECHClientHelloCodec {
  public static let encryptedClientHelloExtensionType: UInt16 = 0xFE0D
  public static let outerExtensionsType: UInt16 = 0xFD00

  internal static func makeInner(
    from template: Span<UInt8>,
    maximumNameLength: UInt8,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> ECHPreparedInner {
    let templateBody = try body(of: template)
    let layout = try parseBody(
      templateBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let templateExtensions = templateBody.extracting(layout.extensionsRange)
    let entries = try parseExtensions(templateExtensions)
    guard !entries.contains(where: { $0.type == encryptedClientHelloExtensionType }),
      !entries.contains(where: { $0.type == outerExtensionsType })
    else {
      throw .invalidClientHello
    }

    var innerExtensions = ContiguousArray<UInt8>()
    innerExtensions.reserveCapacity(templateExtensions.count + 5)
    var inserted = false
    var entryIndex = 0
    while entryIndex < entries.count {
      let entry = entries[entryIndex]
      if !inserted, entry.type == TLS13PreSharedKeyExtension.extensionType {
        appendInnerExtension(to: &innerExtensions)
        inserted = true
      }
      append(templateExtensions.extracting(entry.range), to: &innerExtensions)
      entryIndex += 1
    }
    if !inserted { appendInnerExtension(to: &innerExtensions) }
    guard innerExtensions.count <= UInt16.max else { throw .invalidClientHello }

    var innerBody = ContiguousArray<UInt8>()
    innerBody.reserveCapacity(templateBody.count + 5)
    append(templateBody.extracting(0..<layout.extensionsLengthOffset), to: &innerBody)
    appendUInt16(UInt16(innerExtensions.count), to: &innerBody)
    innerBody.append(contentsOf: innerExtensions)
    let innerClientHello = try finishHandshake(body: innerBody.span)

    let innerLayout = try parseBody(
      innerBody.span,
      allowTrailingPadding: false,
      encoding: encoding
    )
    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(innerBody.count + Int(maximumNameLength) + 41)
    append(innerBody.span.extracting(0..<innerLayout.sessionIDLengthOffset), to: &encoded)
    encoded.append(0)
    append(
      innerBody.span.extracting(innerLayout.sessionIDRange.upperBound..<innerBody.count),
      to: &encoded
    )

    let nameLength = try serverNameLength(in: innerExtensions.span)
    if let nameLength, nameLength < Int(maximumNameLength) {
      appendZeros(Int(maximumNameLength) - nameLength, to: &encoded)
    } else if nameLength == nil {
      appendZeros(Int(maximumNameLength) + 9, to: &encoded)
    }
    let finalPadding = (32 - (encoded.count & 31)) & 31
    appendZeros(finalPadding, to: &encoded)
    return ECHPreparedInner(
      clientHello: innerClientHello,
      encoded: OwnedBytes(consuming: encoded)
    )
  }

  internal static func makeRetriedInner(
    from clientHello: Span<UInt8>,
    maximumNameLength: UInt8,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> ECHPreparedInner {
    let body = try body(of: clientHello)
    let layout = try parseBody(
      body,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let extensions = body.extracting(layout.extensionsRange)
    let entries = try parseExtensions(extensions)
    guard entries.filter({
      $0.type == encryptedClientHelloExtensionType
    }).count == 1,
      !entries.contains(where: { $0.type == outerExtensionsType }),
      let ech = entries.first(where: {
        $0.type == encryptedClientHelloExtensionType
      })
    else {
      throw .invalidClientHello
    }
    let echValue = extensions.extracting(ech.valueRange)
    guard echValue.count == 1, echValue[0] == 1 else {
      throw .invalidClientHello
    }

    var encoded = ContiguousArray<UInt8>()
    encoded.reserveCapacity(body.count + Int(maximumNameLength) + 41)
    append(body.extracting(0..<layout.sessionIDLengthOffset), to: &encoded)
    encoded.append(0)
    append(
      body.extracting(layout.sessionIDRange.upperBound..<body.count),
      to: &encoded
    )
    let nameLength = try serverNameLength(in: extensions)
    if let nameLength, nameLength < Int(maximumNameLength) {
      appendZeros(Int(maximumNameLength) - nameLength, to: &encoded)
    } else if nameLength == nil {
      appendZeros(Int(maximumNameLength) + 9, to: &encoded)
    }
    appendZeros((32 - (encoded.count & 31)) & 31, to: &encoded)
    return ECHPreparedInner(
      clientHello: OwnedBytes(copying: clientHello),
      encoded: OwnedBytes(consuming: encoded)
    )
  }

  internal static func isEncodedInner(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> Bool {
    let messageBody = try body(of: message)
    let layout = try parseBody(
      messageBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let extensionBytes = messageBody.extracting(layout.extensionsRange)
    let entries = try parseExtensions(extensionBytes)
    let encryptedClientHelloEntries = entries.filter {
      $0.type == encryptedClientHelloExtensionType
    }
    guard encryptedClientHelloEntries.count <= 1 else {
      throw .invalidClientHello
    }
    guard let encryptedClientHello = encryptedClientHelloEntries.first else {
      return false
    }
    let value = extensionBytes.extracting(encryptedClientHello.valueRange)
    return value.count == 1 && value[0] == 1
  }

  internal static func makeOuterAAD(
    from template: Span<UInt8>,
    cipherSuite: ECHCipherSuite,
    configID: UInt8,
    encapsulation: Span<UInt8>,
    payloadByteCount: Int,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> ECHOuterAAD {
    guard payloadByteCount > 0, payloadByteCount <= UInt16.max,
      encapsulation.count <= UInt16.max
    else {
      throw .invalidClientHello
    }
    let templateBody = try body(of: template)
    let layout = try parseBody(
      templateBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let templateExtensions = templateBody.extracting(layout.extensionsRange)
    let entries = try parseExtensions(templateExtensions)
    guard !entries.contains(where: { $0.type == encryptedClientHelloExtensionType }),
      !entries.contains(where: { $0.type == TLS13PreSharedKeyExtension.extensionType })
    else {
      throw .invalidClientHello
    }

    let valueByteCount = 1 + 4 + 1 + 2 + encapsulation.count + 2 + payloadByteCount
    let extensionByteCount = 4 + valueByteCount
    let (newExtensionsByteCount, overflow) = templateExtensions.count.addingReportingOverflow(
      extensionByteCount
    )
    guard !overflow, newExtensionsByteCount <= UInt16.max else {
      throw .invalidClientHello
    }
    var aad = ContiguousArray<UInt8>()
    aad.reserveCapacity(templateBody.count + extensionByteCount)
    append(templateBody.extracting(0..<layout.extensionsLengthOffset), to: &aad)
    appendUInt16(UInt16(newExtensionsByteCount), to: &aad)
    append(templateExtensions, to: &aad)
    appendUInt16(encryptedClientHelloExtensionType, to: &aad)
    appendUInt16(UInt16(valueByteCount), to: &aad)
    aad.append(0)
    appendUInt16(cipherSuite.kdfIdentifier, to: &aad)
    appendUInt16(cipherSuite.aeadIdentifier, to: &aad)
    aad.append(configID)
    appendUInt16(UInt16(encapsulation.count), to: &aad)
    append(encapsulation, to: &aad)
    appendUInt16(UInt16(payloadByteCount), to: &aad)
    let payloadOffset = aad.count
    appendZeros(payloadByteCount, to: &aad)
    guard aad.count <= 0xFF_FFFF else { throw .invalidClientHello }
    let payloadRange: ByteRange
    do {
      payloadRange = try ByteRange(offset: payloadOffset, count: payloadByteCount)
    } catch {
      throw .invalidClientHello
    }
    return ECHOuterAAD(body: OwnedBytes(consuming: aad), payloadRange: payloadRange)
  }

  internal static func parseOuter(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> ECHParsedOuter {
    let messageBody = try body(of: message)
    let layout = try parseBody(
      messageBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let extensionBytes = messageBody.extracting(layout.extensionsRange)
    let entries = try parseExtensions(extensionBytes)
    guard let ech = entries.first(where: { $0.type == encryptedClientHelloExtensionType }) else {
      throw .invalidClientHello
    }
    var cursor = ByteCursor(extensionBytes.extracting(ech.valueRange))
    do {
      guard try cursor.readByte() == 0 else { throw ECHError.invalidClientHello }
      let suite = ECHCipherSuite(
        kdfIdentifier: try cursor.readUInt16BigEndian(),
        aeadIdentifier: try cursor.readUInt16BigEndian()
      )
      let configID = try cursor.readByte()
      let encapsulationByteCount = Int(try cursor.readUInt16BigEndian())
      let encapsulationStartInExtensionValue = cursor.offset
      _ = try cursor.readSpan(count: encapsulationByteCount)
      let payloadByteCount = Int(try cursor.readUInt16BigEndian())
      guard payloadByteCount > 0 else { throw ECHError.invalidClientHello }
      let payloadStartInExtensionValue = cursor.offset
      _ = try cursor.readSpan(count: payloadByteCount)
      try cursor.requireFullyConsumed()
      let payloadOffset =
        layout.extensionsRange.lowerBound
        + ech.valueRange.lowerBound + payloadStartInExtensionValue
      let encapsulationOffset =
        layout.extensionsRange.lowerBound
        + ech.valueRange.lowerBound + encapsulationStartInExtensionValue
      let encapsulationRange = try ByteRange(
        offset: encapsulationOffset,
        count: encapsulationByteCount
      )
      let payloadRange = try ByteRange(
        offset: payloadOffset,
        count: payloadByteCount
      )
      var authenticatedBody = copy(messageBody)
      var payloadIndex = payloadRange.offset
      while payloadIndex < payloadRange.endOffset {
        authenticatedBody[payloadIndex] = 0
        payloadIndex += 1
      }
      return ECHParsedOuter(
        body: OwnedBytes(consuming: authenticatedBody),
        sessionIDRange: try ByteRange(
          offset: layout.sessionIDRange.lowerBound,
          count: layout.sessionIDRange.count
        ),
        cipherSuite: suite,
        configID: configID,
        encapsulationRange: encapsulationRange,
        payloadRange: payloadRange
      )
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidClientHello
    }
  }

  internal static func containsOuterECH(
    _ message: Span<UInt8>,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> Bool {
    let messageBody = try body(of: message)
    let layout = try parseBody(
      messageBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let extensionBytes = messageBody.extracting(layout.extensionsRange)
    return try parseExtensions(extensionBytes).contains {
      $0.type == encryptedClientHelloExtensionType
    }
  }

  internal static func reconstructInner(
    encoded: Span<UInt8>,
    outer: ECHParsedOuter,
    encoding: TLS13HandshakeEncoding = .tls13
  ) throws(ECHError) -> OwnedBytes {
    let layout = try parseBody(
      encoded,
      allowTrailingPadding: true,
      encoding: encoding
    )
    guard layout.sessionIDRange.isEmpty else { throw .invalidClientHello }
    var paddingIndex = layout.bodyEnd
    while paddingIndex < encoded.count {
      guard encoded[paddingIndex] == 0 else { throw .invalidPadding }
      paddingIndex += 1
    }
    let innerExtensions = encoded.extracting(layout.extensionsRange)
    let expandedExtensions = try expandOuterExtensions(
      inner: innerExtensions,
      outerBody: outer.body.span,
      encoding: encoding
    )
    try validateInnerExtensions(expandedExtensions.span, encoding: encoding)
    guard expandedExtensions.count <= UInt16.max else { throw .invalidClientHello }
    guard outer.body.contains(outer.sessionIDRange) else { throw .invalidClientHello }
    let sessionID = outer.body.span.extracting(
      outer.sessionIDRange.offset..<outer.sessionIDRange.endOffset
    )

    var body = ContiguousArray<UInt8>()
    body.reserveCapacity(layout.bodyEnd + sessionID.count + expandedExtensions.count)
    append(encoded.extracting(0..<layout.sessionIDLengthOffset), to: &body)
    guard sessionID.count <= UInt8.max else { throw .invalidClientHello }
    body.append(UInt8(sessionID.count))
    append(sessionID, to: &body)
    append(
      encoded.extracting(layout.sessionIDRange.upperBound..<layout.extensionsLengthOffset),
      to: &body
    )
    appendUInt16(UInt16(expandedExtensions.count), to: &body)
    body.append(contentsOf: expandedExtensions)
    return try finishHandshake(body: body.span)
  }

  internal static func makeHPKEInfo(config: ECHConfig) -> OwnedBytes {
    var info: ContiguousArray<UInt8> = [
      0x74, 0x6C, 0x73, 0x20, 0x65, 0x63, 0x68, 0x00,
    ]
    config.withEncodedBytes { append($0, to: &info) }
    return OwnedBytes(consuming: info)
  }

  internal static func finishOuter(
    aad: ECHOuterAAD,
    fillingCiphertext fillCiphertext: (inout MutableSpan<UInt8>) throws(ECHError) -> Void
  ) throws(ECHError) -> OwnedBytes {
    guard aad.body.count <= 0xFF_FFFF, aad.body.contains(aad.payloadRange) else {
      throw .invalidClientHello
    }
    let (resultByteCount, countOverflow) = aad.body.count.addingReportingOverflow(4)
    let (payloadOffset, offsetOverflow) = aad.payloadRange.offset.addingReportingOverflow(4)
    guard !countOverflow, !offsetOverflow else { throw .invalidClientHello }

    var result = ContiguousArray<UInt8>(repeating: 0, count: resultByteCount)
    result[0] = TLS13HandshakeCodec.clientHelloType
    result[1] = UInt8(truncatingIfNeeded: aad.body.count >> 16)
    result[2] = UInt8(truncatingIfNeeded: aad.body.count >> 8)
    result[3] = UInt8(truncatingIfNeeded: aad.body.count)
    var index = 0
    while index < aad.body.count {
      result[4 + index] = aad.body[index]
      index += 1
    }
    try result.withUnsafeMutableBufferPointer { buffer throws(ECHError) in
      // Unsafe boundary invariants:
      // - `result` exclusively owns one initialized contiguous allocation.
      // - The validated payload range and four-byte header bound this subspan.
      // - The pointer remains inside this synchronous closure and cannot escape.
      // - UInt8 has unit stride/alignment and no binding conversion is performed.
      // - ContiguousArray performs exactly-once deallocation after ownership transfer.
      let start = buffer.baseAddress.unsafelyUnwrapped.advanced(by: payloadOffset)
      var destination = MutableSpan(
        _unsafeStart: start,
        count: aad.payloadRange.count
      )
      try fillCiphertext(&destination)
    }
    return OwnedBytes(consuming: result)
  }

  private static func expandOuterExtensions(
    inner: Span<UInt8>,
    outerBody: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) -> ContiguousArray<UInt8> {
    let innerEntries = try parseExtensions(inner)
    guard let marker = innerEntries.first(where: { $0.type == outerExtensionsType }) else {
      return copy(inner)
    }
    let outerLayout = try parseBody(
      outerBody,
      allowTrailingPadding: false,
      encoding: encoding
    )
    let outerExtensionBytes = outerBody.extracting(outerLayout.extensionsRange)
    let outerEntries = try parseExtensions(outerExtensionBytes)
    var listCursor = ByteCursor(inner.extracting(marker.valueRange))
    let requested: Span<UInt8>
    do {
      let byteCount = Int(try listCursor.readByte())
      guard byteCount >= 2, byteCount <= 254, byteCount.isMultiple(of: 2) else {
        throw ECHError.invalidOuterExtension
      }
      requested = try listCursor.readSpan(count: byteCount)
      try listCursor.requireFullyConsumed()
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidOuterExtension
    }

    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(inner.count + outerExtensionBytes.count)
    append(inner.extracting(0..<marker.range.lowerBound), to: &result)
    var requestedCursor = ByteCursor(requested)
    var outerIndex = 0
    var seen = ContiguousArray<UInt16>()
    do {
      while !requestedCursor.isAtEnd {
        let wanted = try requestedCursor.readUInt16BigEndian()
        guard wanted != encryptedClientHelloExtensionType,
          !seen.contains(wanted)
        else {
          throw ECHError.invalidOuterExtension
        }
        seen.append(wanted)
        while outerIndex < outerEntries.count, outerEntries[outerIndex].type != wanted {
          outerIndex += 1
        }
        guard outerIndex < outerEntries.count else {
          throw ECHError.invalidOuterExtension
        }
        append(
          outerExtensionBytes.extracting(outerEntries[outerIndex].range),
          to: &result
        )
        outerIndex += 1
      }
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidOuterExtension
    }
    append(inner.extracting(marker.range.upperBound..<inner.count), to: &result)
    _ = try parseExtensions(result.span)
    return result
  }

  private static func validateInnerExtensions(
    _ extensions: Span<UInt8>,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) {
    let entries = try parseExtensions(extensions)
    guard let ech = entries.first(where: { $0.type == encryptedClientHelloExtensionType }),
      extensions.extracting(ech.valueRange).count == 1,
      extensions[ech.valueRange.lowerBound] == 1,
      !entries.contains(where: { $0.type == outerExtensionsType })
    else {
      throw .invalidClientHello
    }
    guard let versions = entries.first(where: { $0.type == 0x002B }) else {
      throw .invalidClientHello
    }
    var cursor = ByteCursor(extensions.extracting(versions.valueRange))
    do {
      let byteCount = Int(try cursor.readByte())
      guard byteCount >= 2, byteCount.isMultiple(of: 2), byteCount == cursor.remainingCount else {
        throw ECHError.invalidClientHello
      }
      var sawNegotiatedVersion = false
      while !cursor.isAtEnd {
        let version = try cursor.readUInt16BigEndian()
        if version == encoding.negotiatedVersion {
          sawNegotiatedVersion = true
        }
      }
      guard sawNegotiatedVersion else { throw ECHError.invalidClientHello }
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidClientHello
    }
  }

  private static func serverNameLength(
    in extensions: Span<UInt8>
  ) throws(ECHError) -> Int? {
    let entries = try parseExtensions(extensions)
    guard let serverName = entries.first(where: { $0.type == 0x0000 }) else {
      return nil
    }
    var cursor = ByteCursor(extensions.extracting(serverName.valueRange))
    do {
      let listByteCount = Int(try cursor.readUInt16BigEndian())
      guard listByteCount == cursor.remainingCount, listByteCount >= 3 else {
        throw ECHError.invalidClientHello
      }
      guard try cursor.readByte() == 0 else { throw ECHError.invalidClientHello }
      let nameByteCount = Int(try cursor.readUInt16BigEndian())
      guard nameByteCount > 0 else { throw ECHError.invalidClientHello }
      _ = try cursor.readSpan(count: nameByteCount)
      try cursor.requireFullyConsumed()
      return nameByteCount
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidClientHello
    }
  }

  private static func body(of message: Span<UInt8>) throws(ECHError) -> Span<UInt8> {
    guard message.count >= 4, message[0] == TLS13HandshakeCodec.clientHelloType else {
      throw .invalidClientHello
    }
    let byteCount = (Int(message[1]) << 16) | (Int(message[2]) << 8) | Int(message[3])
    guard byteCount == message.count - 4 else { throw .invalidClientHello }
    return message.extracting(4..<message.count)
  }

  private static func parseBody(
    _ body: Span<UInt8>,
    allowTrailingPadding: Bool,
    encoding: TLS13HandshakeEncoding
  ) throws(ECHError) -> ECHClientHelloLayout {
    var cursor = ByteCursor(body)
    do {
      guard try cursor.readUInt16BigEndian() == encoding.legacyVersion else {
        throw ECHError.invalidClientHello
      }
      _ = try cursor.readSpan(count: 32)
      let sessionIDLengthOffset = cursor.offset
      let sessionIDByteCount = Int(try cursor.readByte())
      guard sessionIDByteCount <= 32 else { throw ECHError.invalidClientHello }
      let sessionIDStart = cursor.offset
      _ = try cursor.readSpan(count: sessionIDByteCount)
      let sessionIDRange = sessionIDStart..<cursor.offset
      if encoding.includesLegacyCookie {
        let cookieByteCount = Int(try cursor.readByte())
        _ = try cursor.readSpan(count: cookieByteCount)
      }
      let cipherSuiteByteCount = Int(try cursor.readUInt16BigEndian())
      guard cipherSuiteByteCount >= 2, cipherSuiteByteCount.isMultiple(of: 2) else {
        throw ECHError.invalidClientHello
      }
      _ = try cursor.readSpan(count: cipherSuiteByteCount)
      let compressionByteCount = Int(try cursor.readByte())
      guard compressionByteCount > 0 else { throw ECHError.invalidClientHello }
      _ = try cursor.readSpan(count: compressionByteCount)
      let extensionsLengthOffset = cursor.offset
      let extensionsByteCount = Int(try cursor.readUInt16BigEndian())
      let extensionsStart = cursor.offset
      _ = try cursor.readSpan(count: extensionsByteCount)
      let extensionsRange = extensionsStart..<cursor.offset
      let bodyEnd = cursor.offset
      if !allowTrailingPadding { try cursor.requireFullyConsumed() }
      _ = try parseExtensions(body.extracting(extensionsRange))
      return ECHClientHelloLayout(
        sessionIDLengthOffset: sessionIDLengthOffset,
        sessionIDRange: sessionIDRange,
        extensionsLengthOffset: extensionsLengthOffset,
        extensionsRange: extensionsRange,
        bodyEnd: bodyEnd
      )
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidClientHello
    }
  }

  private static func parseExtensions(
    _ extensions: Span<UInt8>
  ) throws(ECHError) -> ContiguousArray<ECHRawExtension> {
    var cursor = ByteCursor(extensions)
    var result = ContiguousArray<ECHRawExtension>()
    do {
      while !cursor.isAtEnd {
        let start = cursor.offset
        let type = try cursor.readUInt16BigEndian()
        guard !result.contains(where: { $0.type == type }) else {
          throw ECHError.invalidClientHello
        }
        let valueByteCount = Int(try cursor.readUInt16BigEndian())
        let valueStart = cursor.offset
        _ = try cursor.readSpan(count: valueByteCount)
        result.append(
          ECHRawExtension(
            type: type,
            range: start..<cursor.offset,
            valueRange: valueStart..<cursor.offset
          ))
        if type == TLS13PreSharedKeyExtension.extensionType, !cursor.isAtEnd {
          throw ECHError.invalidClientHello
        }
      }
      return result
    } catch let error as ECHError {
      throw error
    } catch {
      throw .invalidClientHello
    }
  }

  private static func appendInnerExtension(
    to bytes: inout ContiguousArray<UInt8>
  ) {
    appendUInt16(encryptedClientHelloExtensionType, to: &bytes)
    appendUInt16(1, to: &bytes)
    bytes.append(1)
  }

  private static func finishHandshake(
    body: Span<UInt8>
  ) throws(ECHError) -> OwnedBytes {
    guard body.count <= 0xFF_FFFF else { throw .invalidClientHello }
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(body.count + 4)
    result.append(TLS13HandshakeCodec.clientHelloType)
    result.append(UInt8(truncatingIfNeeded: body.count >> 16))
    result.append(UInt8(truncatingIfNeeded: body.count >> 8))
    result.append(UInt8(truncatingIfNeeded: body.count))
    append(body, to: &result)
    return OwnedBytes(consuming: result)
  }

  private static func appendUInt16(
    _ value: UInt16,
    to bytes: inout ContiguousArray<UInt8>
  ) {
    bytes.append(UInt8(truncatingIfNeeded: value >> 8))
    bytes.append(UInt8(truncatingIfNeeded: value))
  }

  private static func appendZeros(
    _ count: Int,
    to bytes: inout ContiguousArray<UInt8>
  ) {
    guard count > 0 else { return }
    bytes.append(contentsOf: repeatElement(0, count: count))
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

  private static func copy(_ source: Span<UInt8>) -> ContiguousArray<UInt8> {
    var result = ContiguousArray<UInt8>()
    result.reserveCapacity(source.count)
    append(source, to: &result)
    return result
  }
}

internal struct ECHPreparedInner: Sendable {
  let clientHello: OwnedBytes
  let encoded: OwnedBytes
}

internal struct ECHOuterAAD: Sendable {
  let body: OwnedBytes
  let payloadRange: ByteRange
}

internal struct ECHParsedOuter: Sendable {
  let body: OwnedBytes
  let sessionIDRange: ByteRange
  let cipherSuite: ECHCipherSuite
  let configID: UInt8
  let encapsulationRange: ByteRange
  let payloadRange: ByteRange
}

private struct ECHClientHelloLayout {
  let sessionIDLengthOffset: Int
  let sessionIDRange: Range<Int>
  let extensionsLengthOffset: Int
  let extensionsRange: Range<Int>
  let bodyEnd: Int
}

private struct ECHRawExtension {
  let type: UInt16
  let range: Range<Int>
  let valueRange: Range<Int>
}
