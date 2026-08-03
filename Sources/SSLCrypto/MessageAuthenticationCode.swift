import SSLCore

public protocol MessageAuthenticationCode: Sendable {
  associatedtype Context: ~Copyable & MessageAuthenticationCodeContext

  static var tagByteCount: Int { get }

  static func makeContext(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) -> Context

  /// Writes exactly `tagByteCount` bytes into an equally sized output.
  ///
  /// Implementations must reject any other output size before modifying it.
  static func authenticate(
    _ message: Span<UInt8>,
    using key: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)

  static func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>,
    authenticating message: Span<UInt8>,
    using key: Span<UInt8>
  ) throws(CryptoInputError) -> Bool
}

extension MessageAuthenticationCode {
  public static func authenticate(
    _ message: Span<UInt8>,
    using key: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    var context = try makeContext(authenticatingWith: key)
    try context.update(message)
    try context.finalize(into: &output)
  }

  public static func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>,
    authenticating message: Span<UInt8>,
    using key: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    var context = try makeContext(authenticatingWith: key)
    try context.update(message)
    return try context.isValidAuthenticationCode(authenticationCode)
  }
}
