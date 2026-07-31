import SwiftSSLCore

public struct HMACSHA256Context: ~Copyable, MessageAuthenticationCodeContext {
  // The noncopyable public owner keeps the private state reference unique.
  // The final backing object provides a stable address so its key-derived
  // fields can be wiped in place before ARC releases the allocation.
  private let state: HMACSHA256ContextStorage

  public init(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) {
    let state = HMACSHA256ContextStorage()
    try state.initialize(authenticatingWith: key)
    self.state = state
  }

  public mutating func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError) {
    try state.update(input)
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try state.finalize(into: &output)
  }

  public consuming func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    try state.isValidAuthenticationCode(authenticationCode)
  }
}
