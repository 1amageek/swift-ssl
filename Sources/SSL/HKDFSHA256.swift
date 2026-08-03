import SSLCrypto

/// RFC 5869 HKDF instantiated with HMAC-SHA-256.
public enum HKDFSHA256: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError

  public static let pseudorandomKeyByteCount = SHA256.digestByteCount
  public static let maximumOutputByteCount =
    SSLCrypto.HKDFSHA256.maximumOutputByteCount

  public static func extract(
    inputKeyMaterial: Span<UInt8>,
    salt: Span<UInt8>,
    into pseudorandomKey: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA256.extract(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        into: &pseudorandomKey
      )
    } catch {
      throw HKDFError(error)
    }
  }

  public static func expand(
    pseudorandomKey: Span<UInt8>,
    info: Span<UInt8>,
    into outputKeyMaterial: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA256.expand(
        pseudorandomKey: pseudorandomKey,
        info: info,
        into: &outputKeyMaterial
      )
    } catch {
      throw HKDFError(error)
    }
  }
}
