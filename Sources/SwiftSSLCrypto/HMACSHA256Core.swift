import SwiftSSLCore

/// Allocation-free HMAC-SHA-256 operations for lexically scoped use.
enum HMACSHA256Core {
  private static let blockByteCount = 64
  private static let innerPad: UInt8 = 0x36
  private static let outerPad: UInt8 = 0x5C

  static func withPreparedContexts<Result>(
    authenticatingWith key: Span<UInt8>,
    _ body: (
      borrowing SHA256Context,
      borrowing SHA256Context
    ) throws(CryptoInputError) -> Result
  ) throws(CryptoInputError) -> Result {
    var innerContext = SHA256Context()
    var outerContext = SHA256Context()
    defer {
      innerContext.eraseSensitiveState()
      outerContext.eraseSensitiveState()
    }

    try initializeFreshContexts(
      authenticatingWith: key,
      innerContext: &innerContext,
      outerContext: &outerContext
    )
    return try body(innerContext, outerContext)
  }

  static func initializeFreshContexts(
    authenticatingWith key: Span<UInt8>,
    innerContext: inout SHA256Context,
    outerContext: inout SHA256Context
  ) throws(CryptoInputError) {
    var keyBlock = SIMD64<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - keyBlock owns exactly 64 initialized UInt8 values for this synchronous
    //   closure, with stride and alignment one for byte access.
    // - The derived pointer and all spans remain inside the closure.
    // - The 32-byte mutable span is used only for SHA-256 key normalization.
    // - The normalization context is wiped before leaving its lexical scope.
    // - Both fresh contexts borrow the block only during update and retain no
    //   pointer to it.
    // - No alias crosses a Sendable boundary, and keyBlock is wiped before the
    //   closure returns on both success and failure.
    try withUnsafeMutableBytes(of: &keyBlock) {
      rawBytes throws(CryptoInputError) in
      let rawPointer = rawBytes.baseAddress!
      defer {
        SecureWipe.erase(rawPointer, byteCount: rawBytes.count)
      }

      let bytePointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      if key.count > Self.blockByteCount {
        var normalizedKey = MutableSpan(
          _unsafeStart: bytePointer,
          count: SHA256.digestByteCount
        )
        var normalizationContext = SHA256Context()
        defer {
          normalizationContext.eraseSensitiveState()
        }
        try normalizationContext.update(key)
        try normalizationContext.finalizeInPlace(into: &normalizedKey)
      } else {
        var keyIndex = 0
        while keyIndex < key.count {
          bytePointer[keyIndex] = key[keyIndex]
          keyIndex += 1
        }
      }

      var blockIndex = 0
      while blockIndex < Self.blockByteCount {
        bytePointer[blockIndex] ^= Self.innerPad
        blockIndex += 1
      }

      let blockBuffer = UnsafeBufferPointer(
        start: UnsafePointer(bytePointer),
        count: Self.blockByteCount
      )
      let block = Span(_unsafeElements: blockBuffer)
      try innerContext.update(block)

      blockIndex = 0
      let padDifference = Self.innerPad ^ Self.outerPad
      while blockIndex < Self.blockByteCount {
        bytePointer[blockIndex] ^= padDifference
        blockIndex += 1
      }
      try outerContext.update(block)
    }
  }

  static func withWorkingContexts<Result>(
    innerContext preparedInnerContext: borrowing SHA256Context,
    outerContext preparedOuterContext: borrowing SHA256Context,
    _ body: (
      inout SHA256Context,
      inout SHA256Context
    ) throws(CryptoInputError) -> Result
  ) throws(CryptoInputError) -> Result {
    var innerContext = preparedInnerContext.clone()
    var outerContext = preparedOuterContext.clone()
    defer {
      innerContext.eraseSensitiveState()
      outerContext.eraseSensitiveState()
    }

    return try body(&innerContext, &outerContext)
  }

  static func finalizeAuthenticationCode(
    innerContext: inout SHA256Context,
    outerContext: inout SHA256Context,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == HMACSHA256.tagByteCount else {
      throw .invalidOutputLength(
        expected: HMACSHA256.tagByteCount,
        actual: output.count
      )
    }

    var innerDigest = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - innerDigest owns exactly 32 initialized bytes and remains exclusively
    //   mutable until the inner hash has finalized.
    // - The immutable span is borrowed by outerContext.update only within this
    //   closure; no pointer or span escapes.
    // - The digest is wiped on every exit after it has served as HMAC input.
    try withUnsafeMutableBytes(of: &innerDigest) {
      rawBytes throws(CryptoInputError) in
      let rawPointer = rawBytes.baseAddress!
      defer {
        SecureWipe.erase(rawPointer, byteCount: rawBytes.count)
      }

      let bytePointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var digestOutput = MutableSpan(
        _unsafeStart: bytePointer,
        count: SHA256.digestByteCount
      )
      try innerContext.finalizeInPlace(into: &digestOutput)

      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(bytePointer),
        count: SHA256.digestByteCount
      )
      try outerContext.update(Span(_unsafeElements: buffer))
    }

    try outerContext.finalizeInPlace(into: &output)
  }
}
