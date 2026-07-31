import SwiftSSLCore

public protocol AuthenticatedCipher: ~Copyable {
    static var keyByteCount: Int { get }
    static var nonceByteCount: Int { get }
    static var tagByteCount: Int { get }

    mutating func seal(
        plaintext: Span<UInt8>,
        authenticatedData: Span<UInt8>,
        nonce: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) throws(AEADError)

    mutating func open(
        ciphertextAndTag: Span<UInt8>,
        authenticatedData: Span<UInt8>,
        nonce: Span<UInt8>,
        into output: inout MutableSpan<UInt8>
    ) throws(AEADError)
}
