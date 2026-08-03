import SSLCore

/// Seals and opens identity archives while keeping password and private-key
/// access inside scoped borrows.
public protocol PKCS12IdentityCoding: Sendable {
    func seal(
        privateKey: borrowing PrivateKeyInfo,
        certificates: [CertificateBytes],
        password: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws -> PKCS12Archive

    func open(
        _ archive: borrowing PKCS12Archive,
        password: Span<UInt8>
    ) throws -> PKCS12Identity
}
