
public protocol MessageAuthenticationCodeContext: ~Copyable {
  mutating func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError)

  /// Writes exactly the algorithm's tag size into an equally sized output.
  ///
  /// Implementations must reject any other output size before modifying it.
  consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError)

  /// Returns `false` for an authentication-code mismatch, including an
  /// incorrect code length. Equal-length comparison must be constant time.
  consuming func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool
}
