import SwiftSSLCore

public protocol SignatureVerifier: Sendable {
    associatedtype PublicKey: Sendable

    static func verify(
        signature: Span<UInt8>,
        message: Span<UInt8>,
        using publicKey: borrowing PublicKey
    ) throws(CryptoInputError) -> Bool
}
