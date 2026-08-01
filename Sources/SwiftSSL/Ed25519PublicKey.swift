import SwiftSSLCore
import SwiftSSLCrypto

/// An owned, validated Ed25519 public key exposed by the SwiftSSL façade.
public struct Ed25519PublicKey: Sendable, Equatable {
    let implementation: SwiftSSLCrypto.Ed25519PublicKey

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        do {
            implementation = try SwiftSSLCrypto.Ed25519PublicKey(bytes: bytes)
        } catch {
            throw CryptoInputError(error)
        }
    }

    public var span: Span<UInt8> { implementation.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try implementation.withBorrowedBytes(body)
    }
}
