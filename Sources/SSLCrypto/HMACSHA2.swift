import SSLCore

package protocol HMACSHA2Context: ~Copyable {
  mutating func update(_ input: Span<UInt8>) throws(CryptoInputError)
  mutating func finalizeInPlace(into output: inout MutableSpan<UInt8>) throws(CryptoInputError)
  mutating func eraseSensitiveState()
}

private enum HMACSHA2Core<Hash: HashFunction> where Hash.Context: HMACSHA2Context {
  private static var blockByteCount: Int { 128 }

  static func initialize(
    key: Span<UInt8>,
    inner: inout Hash.Context,
    outer: inout Hash.Context
  ) throws(CryptoInputError) {
    var keyBlock = [UInt8](repeating: 0, count: blockByteCount)
    try keyBlock.withUnsafeMutableBufferPointer { buffer throws(CryptoInputError) -> Void in
      let pointer = buffer.baseAddress!
      defer { SecureWipe.erase(UnsafeMutableRawPointer(pointer), byteCount: buffer.count) }
      if key.count > blockByteCount {
        var normalized = MutableSpan(_unsafeStart: pointer, count: Hash.digestByteCount)
        var context = Hash.makeContext()
        defer { context.eraseSensitiveState() }
        try context.update(key)
        try context.finalizeInPlace(into: &normalized)
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
      let innerBuffer = UnsafeBufferPointer(start: UnsafePointer(pointer), count: blockByteCount)
      try inner.update(Span(_unsafeElements: innerBuffer))
      index = 0
      while index < blockByteCount {
        pointer[index] ^= 0x36 ^ 0x5C
        index += 1
      }
      let outerBuffer = UnsafeBufferPointer(start: UnsafePointer(pointer), count: blockByteCount)
      try outer.update(Span(_unsafeElements: outerBuffer))
    }
  }

  static func finalize(
    inner: inout Hash.Context,
    outer: inout Hash.Context,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard output.count == Hash.digestByteCount else {
      throw .invalidOutputLength(expected: Hash.digestByteCount, actual: output.count)
    }
    var digest = SIMD64<UInt8>(repeating: 0)
    try withUnsafeMutableBytes(of: &digest) { raw throws(CryptoInputError) -> Void in
      let pointer = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
      var digestSpan = MutableSpan(_unsafeStart: pointer, count: Hash.digestByteCount)
      try inner.finalizeInPlace(into: &digestSpan)
      let buffer = UnsafeBufferPointer(start: UnsafePointer(pointer), count: Hash.digestByteCount)
      try outer.update(Span(_unsafeElements: buffer))
      SecureWipe.erase(raw.baseAddress!, byteCount: raw.count)
    }
    try outer.finalizeInPlace(into: &output)
  }

  static func isValid(
    _ code: Span<UInt8>,
    inner: inout Hash.Context,
    outer: inout Hash.Context
  ) throws(CryptoInputError) -> Bool {
    guard code.count == Hash.digestByteCount else { return false }
    var calculated = SIMD64<UInt8>(repeating: 0)
    return try withUnsafeMutableBytes(of: &calculated) { raw throws(CryptoInputError) -> Bool in
      let pointer = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
      var span = MutableSpan(_unsafeStart: pointer, count: Hash.digestByteCount)
      try finalize(inner: &inner, outer: &outer, into: &span)
      let buffer = UnsafeBufferPointer(start: UnsafePointer(pointer), count: Hash.digestByteCount)
      let result = ConstantTime.equal(code, Span(_unsafeElements: buffer))
      SecureWipe.erase(raw.baseAddress!, byteCount: raw.count)
      return result
    }
  }
}

// These owners are intentionally concrete. Static destruction keeps the
// noncopyable inner and outer contexts on one verified ownership path across
// Native, WASM, and Embedded WASM; the algorithmic core above remains generic.
private final class HMACSHA512Storage {
  private var inner: SHA512Context
  private var outer: SHA512Context

  init(key: Span<UInt8>) throws(CryptoInputError) {
    inner = SHA512.makeContext()
    outer = SHA512.makeContext()
    try HMACSHA2Core<SHA512>.initialize(key: key, inner: &inner, outer: &outer)
  }

  func update(_ input: Span<UInt8>) throws(CryptoInputError) { try inner.update(input) }

  func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try HMACSHA2Core<SHA512>.finalize(inner: &inner, outer: &outer, into: &output)
  }

  func isValid(_ code: Span<UInt8>) throws(CryptoInputError) -> Bool {
    try HMACSHA2Core<SHA512>.isValid(code, inner: &inner, outer: &outer)
  }

  deinit {
    inner.eraseSensitiveState()
    outer.eraseSensitiveState()
  }
}

private final class HMACSHA384Storage {
  private var inner: SHA384Context
  private var outer: SHA384Context

  init(key: Span<UInt8>) throws(CryptoInputError) {
    inner = SHA384.makeContext()
    outer = SHA384.makeContext()
    try HMACSHA2Core<SHA384>.initialize(key: key, inner: &inner, outer: &outer)
  }

  func update(_ input: Span<UInt8>) throws(CryptoInputError) { try inner.update(input) }

  func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try HMACSHA2Core<SHA384>.finalize(inner: &inner, outer: &outer, into: &output)
  }

  func isValid(_ code: Span<UInt8>) throws(CryptoInputError) -> Bool {
    try HMACSHA2Core<SHA384>.isValid(code, inner: &inner, outer: &outer)
  }

  deinit {
    inner.eraseSensitiveState()
    outer.eraseSensitiveState()
  }
}

public struct HMACSHA512Context: ~Copyable, MessageAuthenticationCodeContext {
  private let state: HMACSHA512Storage
  public init(authenticatingWith key: Span<UInt8>) throws(CryptoInputError) {
    state = try HMACSHA512Storage(key: key)
  }
  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try state.update(input)
  }
  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try state.finalize(into: &output)
  }
  public consuming func isValidAuthenticationCode(_ authenticationCode: Span<UInt8>)
    throws(CryptoInputError) -> Bool
  { try state.isValid(authenticationCode) }
}

public struct HMACSHA384Context: ~Copyable, MessageAuthenticationCodeContext {
  private let state: HMACSHA384Storage
  public init(authenticatingWith key: Span<UInt8>) throws(CryptoInputError) {
    state = try HMACSHA384Storage(key: key)
  }
  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    try state.update(input)
  }
  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    try state.finalize(into: &output)
  }
  public consuming func isValidAuthenticationCode(_ authenticationCode: Span<UInt8>)
    throws(CryptoInputError) -> Bool
  { try state.isValid(authenticationCode) }
}

public enum HMACSHA512: MessageAuthenticationCode {
  public typealias Context = HMACSHA512Context
  public static let tagByteCount = SHA512.digestByteCount
  public static func makeContext(authenticatingWith key: Span<UInt8>) throws(CryptoInputError)
    -> HMACSHA512Context
  { try HMACSHA512Context(authenticatingWith: key) }
}

public enum HMACSHA384: MessageAuthenticationCode {
  public typealias Context = HMACSHA384Context
  public static let tagByteCount = SHA384.digestByteCount
  public static func makeContext(authenticatingWith key: Span<UInt8>) throws(CryptoInputError)
    -> HMACSHA384Context
  { try HMACSHA384Context(authenticatingWith: key) }
}
