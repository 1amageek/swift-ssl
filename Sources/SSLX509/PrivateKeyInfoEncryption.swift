import SSLCore

/// Encrypts and decrypts PKCS #8 documents without exposing password or
/// plaintext ownership outside scoped borrows and noncopyable owners.
public protocol PrivateKeyInfoEncryption: Sendable {
    func seal(
        _ privateKeyInfo: borrowing PrivateKeyInfo,
        password: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws -> EncryptedPrivateKeyInfo

    func open(
        _ encryptedPrivateKeyInfo: borrowing EncryptedPrivateKeyInfo,
        password: Span<UInt8>
    ) throws -> PrivateKeyInfo
}
