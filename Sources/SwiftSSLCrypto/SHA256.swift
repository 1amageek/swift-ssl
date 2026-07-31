import SwiftSSLCore

public enum SHA256: HashFunction {
    public typealias Context = SHA256Context

    public static let digestByteCount = SHA256Context.digestByteCount

    public static func makeContext() -> SHA256Context {
        SHA256Context()
    }

    @inlinable
    public static func hash(
        _ input: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) throws(CryptoInputError) {
        var context = SHA256Context()
        try context.update(input)
        try context.finalizeInPlace(into: &output)
    }
}
