import SwiftSSLCore

/// RFC 8018 PBKDF2 instantiated with HMAC-SHA-256.
public enum PBKDF2HMACSHA256: PasswordBasedKeyDerivationFunction {
  public static let pseudorandomFunctionOutputByteCount = HMACSHA256.tagByteCount
  public static let maximumOutputByteCount =
    UInt64(UInt32.max) * UInt64(HMACSHA256.tagByteCount)

  public static func deriveKey(
    password: Span<UInt8>,
    salt: Span<UInt8>,
    iterations: UInt32,
    into output: inout MutableSpan<UInt8>
  ) throws(PBKDF2Error) {
    guard iterations > 0 else {
      throw .invalidIterationCount(iterations)
    }
    guard !output.isEmpty else {
      throw .invalidOutputLength(output.count)
    }
    guard UInt64(output.count) <= Self.maximumOutputByteCount else {
      throw .outputTooLong(
        limit: Self.maximumOutputByteCount,
        actual: output.count
      )
    }
    guard
      !Self.overlaps(password, output.span),
      !Self.overlaps(salt, output.span)
    else {
      throw .overlappingInputAndOutput
    }

    do {
      try HMACSHA256Core.withPreparedContexts(
        authenticatingWith: password
      ) {
        preparedInnerContext,
        preparedOuterContext throws(CryptoInputError) in
        var outputOffset = 0
        var blockIndex: UInt32 = 1
        while outputOffset < output.count {
          try Self.deriveBlock(
            salt: salt,
            iterations: iterations,
            blockIndex: blockIndex,
            preparedInnerContext: preparedInnerContext,
            preparedOuterContext: preparedOuterContext,
            outputOffset: outputOffset,
            into: &output
          )
          outputOffset += Swift.min(
            Self.pseudorandomFunctionOutputByteCount,
            output.count - outputOffset
          )
          if outputOffset < output.count {
            blockIndex &+= 1
          }
        }
      }
    } catch let error {
      throw .primitiveFailure(error)
    }
  }

  private static func deriveBlock(
    salt: Span<UInt8>,
    iterations: UInt32,
    blockIndex: UInt32,
    preparedInnerContext: borrowing SHA256Context,
    preparedOuterContext: borrowing SHA256Context,
    outputOffset: Int,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    var current = SIMD32<UInt8>(repeating: 0)
    var next = SIMD32<UInt8>(repeating: 0)
    var accumulated = SIMD32<UInt8>(repeating: 0)
    defer {
      Self.erase(&current)
      Self.erase(&next)
      Self.erase(&accumulated)
    }

    try withUnsafeMutableBytes(of: &current) { rawBytes throws(CryptoInputError) in
      let pointer = rawBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
      var currentOutput = MutableSpan(
        _unsafeStart: pointer,
        count: Self.pseudorandomFunctionOutputByteCount
      )
      try HMACSHA256Core.withWorkingContexts(
        innerContext: preparedInnerContext,
        outerContext: preparedOuterContext
      ) { innerContext, outerContext throws(CryptoInputError) in
        try innerContext.update(salt)
        try Self.update(&innerContext, withBlockIndex: blockIndex)
        try HMACSHA256Core.finalizeAuthenticationCode(
          innerContext: &innerContext,
          outerContext: &outerContext,
          into: &currentOutput
        )
      }
    }
    accumulated = current

    var iteration: UInt32 = 1
    while iteration < iterations {
      try withUnsafeBytes(of: &current) { currentBytes throws(CryptoInputError) in
        let currentSpan = Span(
          _unsafeElements: currentBytes.bindMemory(to: UInt8.self)
        )
        try withUnsafeMutableBytes(of: &next) { nextBytes throws(CryptoInputError) in
          let pointer = nextBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
          var nextOutput = MutableSpan(
            _unsafeStart: pointer,
            count: Self.pseudorandomFunctionOutputByteCount
          )
          try HMACSHA256Core.withWorkingContexts(
            innerContext: preparedInnerContext,
            outerContext: preparedOuterContext
          ) { innerContext, outerContext throws(CryptoInputError) in
            try innerContext.update(currentSpan)
            try HMACSHA256Core.finalizeAuthenticationCode(
              innerContext: &innerContext,
              outerContext: &outerContext,
              into: &nextOutput
            )
          }
        }
      }

      var byte = 0
      while byte < Self.pseudorandomFunctionOutputByteCount {
        accumulated[byte] ^= next[byte]
        byte += 1
      }
      swap(&current, &next)
      iteration &+= 1
    }

    let byteCount = Swift.min(
      Self.pseudorandomFunctionOutputByteCount,
      output.count - outputOffset
    )
    var byte = 0
    while byte < byteCount {
      output[outputOffset + byte] = accumulated[byte]
      byte += 1
    }
  }

  private static func update(
    _ context: inout SHA256Context,
    withBlockIndex blockIndex: UInt32
  ) throws(CryptoInputError) {
    var bytes = SIMD4<UInt8>(
      UInt8(truncatingIfNeeded: blockIndex >> 24),
      UInt8(truncatingIfNeeded: blockIndex >> 16),
      UInt8(truncatingIfNeeded: blockIndex >> 8),
      UInt8(truncatingIfNeeded: blockIndex)
    )
    try withUnsafeBytes(of: &bytes) { rawBytes throws(CryptoInputError) in
      try context.update(
        Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self))
      )
    }
  }

  private static func erase(_ value: inout SIMD32<UInt8>) {
    withUnsafeMutableBytes(of: &value) { bytes in
      SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
    }
  }

  private static func overlaps(
    _ first: Span<UInt8>,
    _ second: Span<UInt8>
  ) -> Bool {
    guard !first.isEmpty, !second.isEmpty else {
      return false
    }

    // Unsafe boundary invariants:
    // - Both spans borrow initialized UInt8 storage synchronously.
    // - Checked address addition treats wrapped ranges as overlapping.
    // - The pointers do not escape and no memory is rebound or mutated.
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
}
