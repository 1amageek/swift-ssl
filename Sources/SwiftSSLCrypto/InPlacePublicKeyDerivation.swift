import SwiftSSLCore

/// A private key that derives its public key into caller-owned contiguous storage.
public protocol InPlacePublicKeyDerivation: ~Copyable, Sendable {
    static var publicKeyByteCount: Int { get }

    borrowing func publicKey(
        into destination: inout MutableSpan<UInt8>
    ) throws(CryptoInputError)
}
