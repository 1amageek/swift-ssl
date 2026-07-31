import SwiftSSLCrypto

public enum HKDFSHA384: ExtractAndExpandKeyDerivationFunction {
    public typealias Failure = HKDFError
    public static let pseudorandomKeyByteCount = SwiftSSLCrypto.HKDFSHA384.pseudorandomKeyByteCount
    public static let maximumOutputByteCount = SwiftSSLCrypto.HKDFSHA384.maximumOutputByteCount
    public static func extract(inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(HKDFError) { do { try SwiftSSLCrypto.HKDFSHA384.extract(inputKeyMaterial: inputKeyMaterial, salt: salt, into: &output) } catch { throw HKDFError(error) } }
    public static func expand(pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(HKDFError) { do { try SwiftSSLCrypto.HKDFSHA384.expand(pseudorandomKey: pseudorandomKey, info: info, into: &output) } catch { throw HKDFError(error) } }
}

public enum HKDFSHA512: ExtractAndExpandKeyDerivationFunction {
    public typealias Failure = HKDFError
    public static let pseudorandomKeyByteCount = SwiftSSLCrypto.HKDFSHA512.pseudorandomKeyByteCount
    public static let maximumOutputByteCount = SwiftSSLCrypto.HKDFSHA512.maximumOutputByteCount
    public static func extract(inputKeyMaterial: Span<UInt8>, salt: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(HKDFError) { do { try SwiftSSLCrypto.HKDFSHA512.extract(inputKeyMaterial: inputKeyMaterial, salt: salt, into: &output) } catch { throw HKDFError(error) } }
    public static func expand(pseudorandomKey: Span<UInt8>, info: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(HKDFError) { do { try SwiftSSLCrypto.HKDFSHA512.expand(pseudorandomKey: pseudorandomKey, info: info, into: &output) } catch { throw HKDFError(error) } }
}
