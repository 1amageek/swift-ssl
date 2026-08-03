import SSLCore

public enum HMACSHA256: MessageAuthenticationCode {
  public typealias Context = HMACSHA256Context

  public static let tagByteCount = SHA256.digestByteCount

  public static func makeContext(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) -> HMACSHA256Context {
    try HMACSHA256Context(authenticatingWith: key)
  }

  public static func authenticate(
    _ message: Span<UInt8>,
    using key: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    try HMACSHA256Core.withPreparedContexts(
      authenticatingWith: key
    ) { innerContext, outerContext throws(CryptoInputError) in
      try HMACSHA256Core.withWorkingContexts(
        innerContext: innerContext,
        outerContext: outerContext
      ) {
        workingInnerContext,
        workingOuterContext throws(CryptoInputError) in
        try workingInnerContext.update(message)
        try HMACSHA256Core.finalizeAuthenticationCode(
          innerContext: &workingInnerContext,
          outerContext: &workingOuterContext,
          into: &output
        )
      }
    }
  }
}
