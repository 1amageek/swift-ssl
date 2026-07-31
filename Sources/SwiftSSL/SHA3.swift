import SwiftSSLCore
import SwiftSSLCrypto

public struct SHA3_256Context: ~Copyable, HashContext {
    public static let digestByteCount = SwiftSSLCrypto.SHA3_256Context.digestByteCount
    private var implementation: SwiftSSLCrypto.SHA3_256Context

    public init() { implementation = SwiftSSLCrypto.SHA3_256Context() }

    private init(implementation: consuming SwiftSSLCrypto.SHA3_256Context) {
        self.implementation = implementation
    }

    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        do { try implementation.update(input) } catch { throw CryptoInputError(error) }
    }

    public borrowing func clone() -> SHA3_256Context {
        SHA3_256Context(implementation: implementation.clone())
    }

    public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
    }
}

public struct SHA3_512Context: ~Copyable, HashContext {
    public static let digestByteCount = SwiftSSLCrypto.SHA3_512Context.digestByteCount
    private var implementation: SwiftSSLCrypto.SHA3_512Context

    public init() { implementation = SwiftSSLCrypto.SHA3_512Context() }

    private init(implementation: consuming SwiftSSLCrypto.SHA3_512Context) {
        self.implementation = implementation
    }

    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        do { try implementation.update(input) } catch { throw CryptoInputError(error) }
    }

    public borrowing func clone() -> SHA3_512Context {
        SHA3_512Context(implementation: implementation.clone())
    }

    public consuming func finalize(into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try implementation.finalize(into: &output) } catch { throw CryptoInputError(error) }
    }
}

public enum SHA3_256: HashFunction {
    public typealias Context = SHA3_256Context
    public static let digestByteCount = SHA3_256Context.digestByteCount
    public static func makeContext() -> SHA3_256Context { SHA3_256Context() }

    public static func hash(_ input: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try SwiftSSLCrypto.SHA3_256.hash(input, into: &output) } catch { throw CryptoInputError(error) }
    }
}

public enum SHA3_512: HashFunction {
    public typealias Context = SHA3_512Context
    public static let digestByteCount = SHA3_512Context.digestByteCount
    public static func makeContext() -> SHA3_512Context { SHA3_512Context() }

    public static func hash(_ input: Span<UInt8>, into output: inout MutableSpan<UInt8>) throws(CryptoInputError) {
        do { try SwiftSSLCrypto.SHA3_512.hash(input, into: &output) } catch { throw CryptoInputError(error) }
    }
}
