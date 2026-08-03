import SSLCrypto

public struct HMACSHA512Context: ~Copyable, MessageAuthenticationCodeContext {
  private var implementation: SSLCrypto.HMACSHA512Context
  public init(authenticatingWith key: Span<UInt8>) throws(CryptoInputError) {
    do { implementation = try SSLCrypto.HMACSHA512Context(authenticatingWith: key) } catch {
      throw CryptoInputError(error)
    }
  }
  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    do { try implementation.update(input) } catch { throw CryptoInputError(error) }
  }
  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
  }
  public consuming func isValidAuthenticationCode(_ code: Span<UInt8>) throws(CryptoInputError)
    -> Bool
  {
    do { return try implementation.isValidAuthenticationCode(code) } catch {
      throw CryptoInputError(error)
    }
  }
}

public struct HMACSHA384Context: ~Copyable, MessageAuthenticationCodeContext {
  private var implementation: SSLCrypto.HMACSHA384Context
  public init(authenticatingWith key: Span<UInt8>) throws(CryptoInputError) {
    do { implementation = try SSLCrypto.HMACSHA384Context(authenticatingWith: key) } catch {
      throw CryptoInputError(error)
    }
  }
  public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
    do { try implementation.update(input) } catch { throw CryptoInputError(error) }
  }
  public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
    do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
  }
  public consuming func isValidAuthenticationCode(_ code: Span<UInt8>) throws(CryptoInputError)
    -> Bool
  {
    do { return try implementation.isValidAuthenticationCode(code) } catch {
      throw CryptoInputError(error)
    }
  }
}

public enum HMACSHA512: MessageAuthenticationCode {
  public typealias Context = HMACSHA512Context
  public static let tagByteCount = SHA512.digestByteCount
  public static func makeContext(authenticatingWith key: Span<UInt8>) throws(CryptoInputError)
    -> HMACSHA512Context
  { try HMACSHA512Context(authenticatingWith: key) }
  public static func authenticate(
    _ message: Span<UInt8>, using key: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do { try SSLCrypto.HMACSHA512.authenticate(message, using: key, into: &output) } catch {
      throw CryptoInputError(error)
    }
  }
}

public enum HMACSHA384: MessageAuthenticationCode {
  public typealias Context = HMACSHA384Context
  public static let tagByteCount = SHA384.digestByteCount
  public static func makeContext(authenticatingWith key: Span<UInt8>) throws(CryptoInputError)
    -> HMACSHA384Context
  { try HMACSHA384Context(authenticatingWith: key) }
  public static func authenticate(
    _ message: Span<UInt8>, using key: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    do { try SSLCrypto.HMACSHA384.authenticate(message, using: key, into: &output) } catch {
      throw CryptoInputError(error)
    }
  }
}
