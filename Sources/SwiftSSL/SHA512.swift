import SwiftSSLCrypto

public enum SHA512: HashFunction {
    public typealias Context = SHA512Context
    public static let digestByteCount = SHA512Context.digestByteCount
    public static func makeContext() -> SHA512Context { SHA512Context() }
    public static func hash(_ input: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try SwiftSSLCrypto.SHA512.hash(input, into: &output) } catch { throw CryptoInputError(error) }
    }
}

public enum SHA384: HashFunction {
    public typealias Context = SHA384Context
    public static let digestByteCount = SHA384Context.digestByteCount
    public static func makeContext() -> SHA384Context { SHA384Context() }
    public static func hash(_ input: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try SwiftSSLCrypto.SHA384.hash(input, into: &output) } catch { throw CryptoInputError(error) }
    }
}

public struct SHA512Context: ~Copyable, HashContext {
    public static let digestByteCount = 64
    private var implementation: SwiftSSLCrypto.SHA512Context
    public init() { implementation = SwiftSSLCrypto.SHA512Context() }
    private init(implementation: consuming SwiftSSLCrypto.SHA512Context) { self.implementation = implementation }
    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        do { try implementation.update(input) } catch { throw CryptoInputError(error) }
    }
    public borrowing func clone() -> SHA512Context { SHA512Context(implementation: implementation.clone()) }
    public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
    }
}

public struct SHA384Context: ~Copyable, HashContext {
    public static let digestByteCount = 48
    private var implementation: SwiftSSLCrypto.SHA384Context
    public init() { implementation = SwiftSSLCrypto.SHA384Context() }
    private init(implementation: consuming SwiftSSLCrypto.SHA384Context) { self.implementation = implementation }
    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        do { try implementation.update(input) } catch { throw CryptoInputError(error) }
    }
    public borrowing func clone() -> SHA384Context { SHA384Context(implementation: implementation.clone()) }
    public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
    }
}
