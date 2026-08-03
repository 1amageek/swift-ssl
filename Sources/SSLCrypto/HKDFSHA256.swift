import SSLCore

/// RFC 5869 HKDF instantiated with HMAC-SHA-256.
public enum HKDFSHA256: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError

  public static let pseudorandomKeyByteCount = SHA256.digestByteCount
  public static let maximumOutputByteCount = 255 * SHA256.digestByteCount

  private static let hmacPadByteCount: UInt64 = 64
  private static let maximumHashInputByteCount = UInt64.max >> 3

  public static func extract(
    inputKeyMaterial: Span<UInt8>,
    salt: Span<UInt8>,
    into pseudorandomKey: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    guard pseudorandomKey.count == Self.pseudorandomKeyByteCount else {
      throw .invalidPseudorandomKeyOutputLength(
        expected: Self.pseudorandomKeyByteCount,
        actual: pseudorandomKey.count
      )
    }
    guard
      !spansOverlap(inputKeyMaterial, pseudorandomKey.span),
      !spansOverlap(salt, pseudorandomKey.span)
    else {
      throw .overlappingInputAndOutput
    }

    do {
      try HMACSHA256.authenticate(
        inputKeyMaterial,
        using: salt,
        into: &pseudorandomKey
      )
    } catch {
      throw mapPrimitiveError(error)
    }
  }

  public static func expand(
    pseudorandomKey: Span<UInt8>,
    info: Span<UInt8>,
    into outputKeyMaterial: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    guard pseudorandomKey.count >= Self.pseudorandomKeyByteCount else {
      throw .pseudorandomKeyTooShort(
        minimum: Self.pseudorandomKeyByteCount,
        actual: pseudorandomKey.count
      )
    }
    guard outputKeyMaterial.count <= Self.maximumOutputByteCount else {
      throw .outputTooLong(
        limit: Self.maximumOutputByteCount,
        actual: outputKeyMaterial.count
      )
    }
    guard
      !spansOverlap(pseudorandomKey, outputKeyMaterial.span),
      !spansOverlap(info, outputKeyMaterial.span)
    else {
      throw .overlappingInputAndOutput
    }
    guard !outputKeyMaterial.isEmpty else {
      return
    }

    try requireValidPrimitiveInputLengths(
      pseudorandomKeyByteCount: pseudorandomKey.count,
      infoByteCount: info.count,
      outputByteCount: outputKeyMaterial.count
    )

    do {
      try HMACSHA256Core.withPreparedContexts(
        authenticatingWith: pseudorandomKey
      ) {
        preparedInnerContext,
        preparedOuterContext throws(CryptoInputError) in
        var outputOffset = 0
        var counter: UInt8 = 1

        while outputOffset < outputKeyMaterial.count {
          try HMACSHA256Core.withWorkingContexts(
            innerContext: preparedInnerContext,
            outerContext: preparedOuterContext
          ) { innerContext, outerContext throws(CryptoInputError) in
            if outputOffset > 0 {
              let previousBlock = outputKeyMaterial.span.extracting(
                (outputOffset - Self.pseudorandomKeyByteCount)..<outputOffset
              )
              try innerContext.update(previousBlock)
            }

            try innerContext.update(info)
            try update(&innerContext, withCounter: counter)

            let remainingByteCount =
              outputKeyMaterial.count - outputOffset
            let currentBlockByteCount = Swift.min(
              Self.pseudorandomKeyByteCount,
              remainingByteCount
            )

            if currentBlockByteCount == Self.pseudorandomKeyByteCount {
              var blockOutput = outputKeyMaterial._mutatingExtracting(
                outputOffset..<(outputOffset + currentBlockByteCount)
              )
              try HMACSHA256Core.finalizeAuthenticationCode(
                innerContext: &innerContext,
                outerContext: &outerContext,
                into: &blockOutput
              )
            } else {
              try finalizePartialBlock(
                innerContext: &innerContext,
                outerContext: &outerContext,
                byteCount: currentBlockByteCount,
                outputOffset: outputOffset,
                into: &outputKeyMaterial
              )
            }

            outputOffset += currentBlockByteCount
            counter &+= 1
          }
        }
      }
    } catch {
      throw mapPrimitiveError(error)
    }
  }

  private static func update(
    _ context: inout SHA256Context,
    withCounter counterValue: UInt8
  ) throws(CryptoInputError) {
    var counter = counterValue

    // Unsafe boundary invariants:
    // - counter owns one initialized UInt8 for this synchronous closure.
    // - UInt8 has stride and alignment one, and the span count is exactly one.
    // - SHA-256 borrows the byte only during update and retains no pointer.
    // - The pointer and span do not escape or cross a Sendable boundary.
    try withUnsafeBytes(of: &counter) {
      rawBytes throws(CryptoInputError) in
      let bytePointer = rawBytes.baseAddress!
        .assumingMemoryBound(to: UInt8.self)
      let buffer = UnsafeBufferPointer(start: bytePointer, count: 1)
      try context.update(Span(_unsafeElements: buffer))
    }
  }

  private static func finalizePartialBlock(
    innerContext: inout SHA256Context,
    outerContext: inout SHA256Context,
    byteCount: Int,
    outputOffset: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    var fullBlock = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - fullBlock owns exactly 32 initialized UInt8 values for this closure.
    // - The mutable span is exclusive while HMAC writes the complete block.
    // - byteCount and outputOffset were derived from a validated output span,
    //   so every copied source and destination index is in bounds.
    // - No pointer or span escapes or crosses a Sendable boundary.
    // - The fixed temporary is wiped on both success and failure.
    try withUnsafeMutableBytes(of: &fullBlock) {
      rawBytes throws(CryptoInputError) in
      let rawPointer = rawBytes.baseAddress!
      defer {
        SecureWipe.erase(rawPointer, byteCount: rawBytes.count)
      }

      let bytePointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var blockOutput = MutableSpan(
        _unsafeStart: bytePointer,
        count: Self.pseudorandomKeyByteCount
      )
      try HMACSHA256Core.finalizeAuthenticationCode(
        innerContext: &innerContext,
        outerContext: &outerContext,
        into: &blockOutput
      )

      output.withUnsafeMutableBytes { outputBytes in
        let destination = outputBytes.baseAddress!.advanced(
          by: outputOffset
        )
        destination.copyMemory(
          from: rawPointer,
          byteCount: byteCount
        )
      }
    }
  }

  private static func requireValidPrimitiveInputLengths(
    pseudorandomKeyByteCount: Int,
    infoByteCount: Int,
    outputByteCount: Int
  ) throws(HKDFError) {
    let pseudorandomKeyByteCount = UInt64(pseudorandomKeyByteCount)
    guard pseudorandomKeyByteCount <= Self.maximumHashInputByteCount else {
      throw .inputTooLong(limit: Self.maximumHashInputByteCount)
    }

    let previousBlockByteCount: UInt64 =
      outputByteCount > Self.pseudorandomKeyByteCount
      ? UInt64(Self.pseudorandomKeyByteCount)
      : 0
    let fixedByteCount =
      Self.hmacPadByteCount + previousBlockByteCount + 1
    let infoByteCount = UInt64(infoByteCount)
    guard
      fixedByteCount <= Self.maximumHashInputByteCount,
      infoByteCount <= Self.maximumHashInputByteCount - fixedByteCount
    else {
      throw .inputTooLong(limit: Self.maximumHashInputByteCount)
    }
  }

  private static func spansOverlap(
    _ first: Span<UInt8>,
    _ second: Span<UInt8>
  ) -> Bool {
    guard !first.isEmpty, !second.isEmpty else {
      return false
    }

    // Unsafe boundary invariants:
    // - Both spans borrow initialized UInt8 storage for these synchronous
    //   closures, and neither pointer escapes.
    // - Counts are nonnegative. Checked address addition rejects an impossible
    //   wrapped range instead of using it as evidence of non-overlap.
    // - The function reads addresses only; it binds, rebinds, and mutates no
    //   memory and crosses no Sendable boundary.
    return first.withUnsafeBufferPointer { firstBuffer in
      second.withUnsafeBufferPointer { secondBuffer in
        let firstStart = UInt(bitPattern: firstBuffer.baseAddress!)
        let secondStart = UInt(bitPattern: secondBuffer.baseAddress!)
        let (firstEnd, firstOverflow) = firstStart.addingReportingOverflow(
          UInt(firstBuffer.count)
        )
        let (secondEnd, secondOverflow) = secondStart.addingReportingOverflow(
          UInt(secondBuffer.count)
        )
        guard !firstOverflow, !secondOverflow else {
          return true
        }
        return firstStart < secondEnd && secondStart < firstEnd
      }
    }
  }

  private static func mapPrimitiveError(
    _ error: CryptoInputError
  ) -> HKDFError {
    switch error {
    case .inputTooLong(let limit):
      .inputTooLong(limit: limit)
    default:
      .primitiveFailure(error)
    }
  }
}
