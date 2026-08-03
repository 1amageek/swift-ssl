import SSLCrypto

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
    do {
      try SSLCrypto.HMACSHA256.authenticate(
        message,
        using: key,
        into: &output
      )
    } catch {
      throw CryptoInputError(error)
    }
  }

  public static func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>,
    authenticating message: Span<UInt8>,
    using key: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    do {
      return try SSLCrypto.HMACSHA256.isValidAuthenticationCode(
        authenticationCode,
        authenticating: message,
        using: key
      )
    } catch {
      throw CryptoInputError(error)
    }
  }
}
