import SwiftSSLCore

// Stable storage owner invariants:
// - The object is created only for one noncopyable HMACSHA256Context, remains
//   internal to this module, and never crosses a Sendable boundary.
// - Its SHA-256 fields stay initialized at fixed offsets for the object's
//   lifetime; methods borrow or mutate them synchronously without retaining
//   input, output, or temporary pointers.
// - deinit wipes both fields in their original object storage before ARC
//   deallocates the object. The optimizer may stack-promote a scoped one-shot
//   use, but the same deinitializer and wipe ordering still apply.
// - ARC owns exactly-once deallocation; this type performs no manual free.
final class HMACSHA256ContextStorage {
  private var innerContext: SHA256Context
  private var outerContext: SHA256Context

  init() {
    innerContext = SHA256Context()
    outerContext = SHA256Context()
  }

  func initialize(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) {
    try HMACSHA256Core.initializeFreshContexts(
      authenticatingWith: key,
      innerContext: &innerContext,
      outerContext: &outerContext
    )
  }

  func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError) {
    try innerContext.update(input)
  }

  func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == HMACSHA256.tagByteCount else {
      throw .invalidOutputLength(
        expected: HMACSHA256.tagByteCount,
        actual: output.count
      )
    }
    try finalizeAuthenticationCode(into: &output)
  }

  func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    guard authenticationCode.count == HMACSHA256.tagByteCount else {
      return false
    }

    var calculatedCode = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - calculatedCode owns exactly 32 initialized bytes for the synchronous
    //   closure and is exclusively mutable while the MutableSpan is live.
    // - The immutable comparison span is created only after finalization and
    //   neither pointer nor span escapes the closure.
    // - ConstantTime.equal reads equal-length buffers, and the calculated tag
    //   is wiped before returning or throwing.
    return try withUnsafeMutableBytes(of: &calculatedCode) {
      rawBytes throws(CryptoInputError) -> Bool in
      let rawPointer = rawBytes.baseAddress!
      defer {
        SecureWipe.erase(rawPointer, byteCount: rawBytes.count)
      }

      let bytePointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var output = MutableSpan(
        _unsafeStart: bytePointer,
        count: HMACSHA256.tagByteCount
      )
      try HMACSHA256Core.finalizeAuthenticationCode(
        innerContext: &innerContext,
        outerContext: &outerContext,
        into: &output
      )

      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(bytePointer),
        count: HMACSHA256.tagByteCount
      )
      let calculated = Span(_unsafeElements: buffer)
      return ConstantTime.equal(authenticationCode, calculated)
    }
  }

  private func eraseSensitiveState() {
    innerContext.eraseSensitiveState()
    outerContext.eraseSensitiveState()
  }

  private func finalizeAuthenticationCode(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try HMACSHA256Core.finalizeAuthenticationCode(
      innerContext: &innerContext,
      outerContext: &outerContext,
      into: &output
    )
  }

  deinit {
    eraseSensitiveState()
  }
}
