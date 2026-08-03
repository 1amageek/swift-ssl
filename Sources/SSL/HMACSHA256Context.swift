import SSLCrypto

public struct HMACSHA256Context:
  ~Copyable,
  MessageAuthenticationCodeContext
{
  private var implementation: SSLCrypto.HMACSHA256Context

  public init(
    authenticatingWith key: Span<UInt8>
  ) throws(CryptoInputError) {
    do {
      implementation = try SSLCrypto.HMACSHA256Context(
        authenticatingWith: key
      )
    } catch {
      throw CryptoInputError(error)
    }
  }

  public mutating func update(
    _ input: Span<UInt8>
  ) throws(CryptoInputError) {
    do {
      try implementation.update(input)
    } catch {
      throw CryptoInputError(error)
    }
  }

  public consuming func finalize(
    into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do {
      try implementation.finalize(into: &output)
    } catch {
      throw CryptoInputError(error)
    }
  }

  public consuming func isValidAuthenticationCode(
    _ authenticationCode: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    do {
      return try implementation.isValidAuthenticationCode(
        authenticationCode
      )
    } catch {
      throw CryptoInputError(error)
    }
  }
}
