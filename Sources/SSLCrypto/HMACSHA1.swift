import SSLCore

/// HMAC-SHA-1 for protocols whose wire specification requires SHA-1.
///
/// New protocols should select a modern MAC. This implementation exists for
/// standards such as STUN message integrity and the AES-CM SRTP profile.
public enum HMACSHA1: MessageAuthenticationCode {
  public typealias Context = HMACSHA1Context

  public static let tagByteCount = SHA1Context.digestByteCount

  public static func makeContext(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) -> HMACSHA1Context {
    try HMACSHA1Context(authenticatingWith: key)
  }
}

public struct HMACSHA1Context: ~Copyable, MessageAuthenticationCodeContext {
  private let storage: HMACSHA1ContextStorage

  public init(authenticatingWith key: Span<UInt8>) throws(CryptoInputError) {
    storage = try HMACSHA1ContextStorage(key: key)
  }

  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try storage.update(input)
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try storage.finalize(into: &output)
  }

  public consuming func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    try storage.isValid(authenticationCode)
  }
}

// Stable storage owner invariants:
// - ARC owns exactly-once allocation and deallocation.
// - One noncopyable HMACSHA1Context owns this object and never exposes it.
// - Input and output spans are borrowed synchronously and never retained.
// - Both key-derived hash states are wiped before deallocation.
private final class HMACSHA1ContextStorage {
  private var inner = SHA1Context()
  private var outer = SHA1Context()

  init(key: Span<UInt8>) throws(CryptoInputError) {
    try HMACSHA1Core.initialize(key: key, inner: &inner, outer: &outer)
  }

  func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try inner.update(input)
  }

  func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try HMACSHA1Core.finalize(inner: &inner, outer: &outer, into: &output)
  }

  func isValid(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    guard authenticationCode.count == HMACSHA1.tagByteCount else {
      return false
    }
    var calculatedCode = SIMD32<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - calculatedCode owns 32 initialized bytes for this synchronous scope.
    // - Only the first 20 bytes are exposed to the MAC implementation.
    // - Mutable and immutable borrows do not overlap and cannot escape.
    // - UInt8 has stride and alignment one; no rebinding is required.
    // - The complete temporary is wiped on every exit.
    return try withUnsafeMutableBytes(of: &calculatedCode) {
      rawBytes throws(CryptoInputError) -> Bool in
      let rawPointer = rawBytes.baseAddress!
      defer { SecureWipe.erase(rawPointer, byteCount: rawBytes.count) }
      let pointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var output = MutableSpan(
        _unsafeStart: pointer,
        count: HMACSHA1.tagByteCount
      )
      try HMACSHA1Core.finalize(inner: &inner, outer: &outer, into: &output)
      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(pointer),
        count: HMACSHA1.tagByteCount
      )
      return ConstantTime.equal(
        authenticationCode,
        Span(_unsafeElements: buffer)
      )
    }
  }

  deinit {
    inner.eraseSensitiveState()
    outer.eraseSensitiveState()
  }
}

private enum HMACSHA1Core {
  private static let blockByteCount = 64

  static func initialize(
    key: Span<UInt8>,
    inner: inout SHA1Context,
    outer: inout SHA1Context
  ) throws(CryptoInputError) {
    var keyBlock = SIMD64<UInt8>(repeating: 0)

    // Unsafe boundary invariants:
    // - keyBlock owns exactly 64 initialized UInt8 values for this scope.
    // - The pointer and spans never escape this synchronous closure.
    // - Key normalization writes only the first 20 bytes.
    // - Hash contexts borrow the pad and do not retain its address.
    // - keyBlock is wiped on both success and failure.
    try withUnsafeMutableBytes(of: &keyBlock) {
      rawBytes throws(CryptoInputError) in
      let rawPointer = rawBytes.baseAddress!
      defer { SecureWipe.erase(rawPointer, byteCount: rawBytes.count) }
      let pointer = rawPointer.assumingMemoryBound(to: UInt8.self)

      if key.count > blockByteCount {
        var normalizedKey = MutableSpan(
          _unsafeStart: pointer,
          count: SHA1Context.digestByteCount
        )
        var normalizationContext = SHA1Context()
        defer { normalizationContext.eraseSensitiveState() }
        try normalizationContext.update(key)
        try normalizationContext.finalizeInPlace(into: &normalizedKey)
      } else {
        var index = 0
        while index < key.count {
          pointer[index] = key[index]
          index += 1
        }
      }

      var index = 0
      while index < blockByteCount {
        pointer[index] ^= 0x36
        index += 1
      }
      let block = UnsafeBufferPointer(
        start: UnsafePointer(pointer),
        count: blockByteCount
      )
      try inner.update(Span(_unsafeElements: block))

      index = 0
      while index < blockByteCount {
        pointer[index] ^= 0x36 ^ 0x5C
        index += 1
      }
      try outer.update(Span(_unsafeElements: block))
    }
  }

  static func finalize(
    inner: inout SHA1Context,
    outer: inout SHA1Context,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == HMACSHA1.tagByteCount else {
      throw .invalidOutputLength(
        expected: HMACSHA1.tagByteCount,
        actual: output.count
      )
    }

    var innerDigest = SIMD32<UInt8>(repeating: 0)
    // Unsafe boundary invariants mirror the validation buffer above. The
    // digest span is mutable only during finalization, then immutably borrowed
    // for the outer hash, and the complete temporary is always wiped.
    try withUnsafeMutableBytes(of: &innerDigest) {
      rawBytes throws(CryptoInputError) in
      let rawPointer = rawBytes.baseAddress!
      defer { SecureWipe.erase(rawPointer, byteCount: rawBytes.count) }
      let pointer = rawPointer.assumingMemoryBound(to: UInt8.self)
      var digestOutput = MutableSpan(
        _unsafeStart: pointer,
        count: SHA1Context.digestByteCount
      )
      try inner.finalizeInPlace(into: &digestOutput)
      let buffer = UnsafeBufferPointer(
        start: UnsafePointer(pointer),
        count: SHA1Context.digestByteCount
      )
      try outer.update(Span(_unsafeElements: buffer))
    }
    try outer.finalizeInPlace(into: &output)
  }
}
