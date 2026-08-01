import SwiftSSLCore
import SwiftSSLCrypto

/// Noncopyable Ed25519 signing material for the TLS 1.3 modern profile.
///
/// TLS authentication deliberately has one signing capability. Certificate
/// compatibility verification remains in `SwiftSSLX509` and cannot become a
/// private-key operation through this type.
public struct TLS13SigningKey: ~Copyable, Sendable {
    private let key: Ed25519PrivateKey

    public init(ed25519 key: consuming Ed25519PrivateKey) {
        self.key = key
    }

    public var signatureScheme: TLS13SignatureScheme { .ed25519 }

    public borrowing func publicKeyBytes() throws(CryptoInputError) -> ContiguousArray<UInt8> {
        try key.publicKey()
    }

    public borrowing func sign(
        message: Span<UInt8>
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        try key.sign(message: message)
    }
}
