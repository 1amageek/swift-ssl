import SSLCrypto

public enum HKDFSHA384: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError
  public static let pseudorandomKeyByteCount = SSLCrypto.HKDFSHA384.pseudorandomKeyByteCount
  public static let maximumOutputByteCount = SSLCrypto.HKDFSHA384.maximumOutputByteCount
  public static func extract(
    inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA384.extract(
        inputKeyMaterial: inputKeyMaterial, salt: salt, into: &output)
    } catch { throw HKDFError(error) }
  }
  public static func expand(
    pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA384.expand(
        pseudorandomKey: pseudorandomKey, info: info, into: &output)
    } catch { throw HKDFError(error) }
  }
}

public enum HKDFSHA512: ExtractAndExpandKeyDerivationFunction {
  public typealias Failure = HKDFError
  public static let pseudorandomKeyByteCount = SSLCrypto.HKDFSHA512.pseudorandomKeyByteCount
  public static let maximumOutputByteCount = SSLCrypto.HKDFSHA512.maximumOutputByteCount
  public static func extract(
    inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA512.extract(
        inputKeyMaterial: inputKeyMaterial, salt: salt, into: &output)
    } catch { throw HKDFError(error) }
  }
  public static func expand(
    pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>
  ) throws(HKDFError) {
    do {
      try SSLCrypto.HKDFSHA512.expand(
        pseudorandomKey: pseudorandomKey, info: info, into: &output)
    } catch { throw HKDFError(error) }
  }
}
