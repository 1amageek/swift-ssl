import SwiftSSLCore

/// The modern PKCS #12 identity profile.
///
/// It supports Ed25519 identities, PBES2/PBKDF2-HMAC-SHA256/AES-256-GCM key
/// protection, and an ordered X.509 chain. It verifies the leaf certificate's
/// public key against the private key both before sealing and after opening.
public struct ModernPKCS12IdentityCodec: PKCS12IdentityCoding, Sendable {
    private let encryption: PBES2AES256GCM

    public init(encryption: PBES2AES256GCM) {
        self.encryption = encryption
    }

    public init() throws(PBES2AES256GCMError) {
        encryption = try PBES2AES256GCM()
    }

    public func seal(
        privateKey: borrowing PrivateKeyInfo,
        certificates: [CertificateBytes],
        password: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws -> PKCS12Archive {
        guard let leafCertificate = certificates.first else {
            throw PKCS12IdentityError.archive(.missingCertificates)
        }
        try PKCS12Ed25519IdentityValidator.validate(
            privateKey: privateKey,
            leafCertificate: leafCertificate
        )

        let encryptedPrivateKey: EncryptedPrivateKeyInfo
        do {
            encryptedPrivateKey = try encryption.seal(
                privateKey,
                password: password,
                using: entropy
            )
        } catch let error as PBES2AES256GCMError {
            throw PKCS12IdentityError.encryption(error)
        }
        do {
            return try PKCS12Archive(
                encryptedPrivateKeyInfo: encryptedPrivateKey,
                certificates: certificates
            )
        } catch let error as PKCS12ArchiveError {
            throw PKCS12IdentityError.archive(error)
        }
    }

    public func open(
        _ archive: borrowing PKCS12Archive,
        password: Span<UInt8>
    ) throws -> PKCS12Identity {
        let encryptedPrivateKey: EncryptedPrivateKeyInfo
        do {
            encryptedPrivateKey = try archive.encryptedPrivateKeyInfo()
        } catch let error as PKCS12ArchiveError {
            throw PKCS12IdentityError.archive(error)
        } catch let error as EncryptedPrivateKeyInfoError {
            throw PKCS12IdentityError.archive(.encryptedPrivateKey(error))
        }

        let privateKey: PrivateKeyInfo
        do {
            privateKey = try encryption.open(
                encryptedPrivateKey,
                password: password
            )
        } catch let error as PBES2AES256GCMError {
            throw PKCS12IdentityError.encryption(error)
        }

        var certificates = ContiguousArray<CertificateBytes>()
        certificates.reserveCapacity(archive.certificateCount)
        var index = 0
        while index < archive.certificateCount {
            do {
                certificates.append(try archive.certificate(at: index))
            } catch let error as PKCS12ArchiveError {
                throw PKCS12IdentityError.archive(error)
            }
            index += 1
        }
        guard let leafCertificate = certificates.first else {
            throw PKCS12IdentityError.archive(.missingCertificates)
        }
        try PKCS12Ed25519IdentityValidator.validate(
            privateKey: privateKey,
            leafCertificate: leafCertificate
        )
        return PKCS12Identity(
            privateKey: privateKey,
            certificates: certificates
        )
    }
}
