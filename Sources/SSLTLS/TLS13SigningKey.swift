import SSLASN1
import SSLCore
import SSLCrypto
import SSLX509

/// Noncopyable signing material for the TLS 1.3 modern profile.
///
/// The closed storage set contains only signature schemes used by the modern
/// TLS profile. Certificate compatibility verification remains in
/// `SSLX509` and cannot become a private-key operation through this type.
public struct TLS13SigningKey: ~Copyable, Sendable {
    private enum Storage: ~Copyable, Sendable {
        case ed25519(Ed25519PrivateKey)
        case p256(P256PrivateKey)
        case rsaPSS(RSAPrivateKey)
    }

    private let storage: Storage

    public init(ed25519 key: consuming Ed25519PrivateKey) {
        storage = .ed25519(key)
    }

    public init(p256 key: consuming P256PrivateKey) {
        storage = .p256(key)
    }

    public init(rsaPSS key: consuming RSAPrivateKey) {
        storage = .rsaPSS(key)
    }

    /// Imports modern TLS signing material from an already validated PKCS #8
    /// owner. The required copy occurs once at the credential boundary so the
    /// algorithm-specific private key can independently own and wipe its bytes.
    public init(
        privateKeyInfo: consuming PrivateKeyInfo
    ) throws(TLS13SigningKeyImportError) {
        switch privateKeyInfo.algorithm {
        case .ed25519:
            guard privateKeyInfo.algorithmIdentifier.parameters == .absent else {
                throw .invalidAlgorithmParameters
            }
            let key: Ed25519PrivateKey = try privateKeyInfo.withPrivateKeyBytes {
                encoded throws(TLS13SigningKeyImportError) -> Ed25519PrivateKey in
                guard encoded.count == Ed25519PrivateKey.seedByteCount + 2,
                    encoded[0] == 0x04,
                    encoded[1] == UInt8(Ed25519PrivateKey.seedByteCount)
                else {
                    throw .malformedPrivateKey
                }
                do {
                    return try Ed25519PrivateKey(
                        seed: encoded.extracting(2..<encoded.count)
                    )
                } catch let error as CryptoInputError {
                    throw .crypto(error)
                } catch {
                    throw .malformedPrivateKey
                }
            }
            self.init(ed25519: key)

        case .ecPublicKey(curve: .prime256v1):
            let encodedKey: ECPrivateKey
            do {
                encodedKey = try privateKeyInfo.ecPrivateKey()
            } catch let error {
                throw .ec(error)
            }
            let key: P256PrivateKey = try encodedKey.withPrivateKeyBytes {
                scalar throws(TLS13SigningKeyImportError) -> P256PrivateKey in
                do {
                    return try P256PrivateKey(bytes: scalar)
                } catch let error as CryptoInputError {
                    throw .crypto(error)
                } catch {
                    throw .malformedPrivateKey
                }
            }
            if let encodedPublicKey = encodedKey.publicKey {
                let derivedPublicKey = key.publicKey()
                let matches = derivedPublicKey.withBorrowedBytes { derived in
                    ConstantTime.equal(derived, encodedPublicKey.span)
                }
                guard matches else { throw .publicKeyMismatch }
            }
            self.init(p256: key)

        case .rsaEncryption:
            guard privateKeyInfo.algorithmIdentifier.parameters == .null
                || privateKeyInfo.algorithmIdentifier.parameters == .absent
            else {
                throw .invalidAlgorithmParameters
            }
            let key: RSAPrivateKey = try privateKeyInfo.withPrivateKeyBytes {
                encoded throws(TLS13SigningKeyImportError) -> RSAPrivateKey in
                do {
                    return try RSAPrivateKey(pkcs1DER: encoded)
                } catch let error as RSAKeyError {
                    throw .rsa(error)
                } catch {
                    throw .malformedPrivateKey
                }
            }
            self.init(rsaPSS: key)

        case .x25519, .ecPublicKey, .unknown:
            throw .unsupportedAlgorithm(privateKeyInfo.algorithm)
        }
    }

    public var signatureScheme: TLS13SignatureScheme {
        switch storage {
        case .ed25519:
            return .ed25519
        case .p256:
            return .ecdsaP256SHA256
        case .rsaPSS:
            return .rsaPSSRSAESHA256
        }
    }

    public borrowing func publicKeyBytes() throws(CryptoInputError) -> ContiguousArray<UInt8> {
        switch storage {
        case .ed25519(let key):
            return try key.publicKey()
        case .p256(let key):
            let publicKey = key.publicKey()
            return publicKey.withBorrowedBytes { bytes in
                Self.copyBytes(bytes)
            }
        case .rsaPSS(let key):
            return key.publicKey.pkcs1DER()
        }
    }

    /// Signs a TLS CertificateVerify input and returns its wire signature.
    public borrowing func sign(
        message: Span<UInt8>
    ) throws(TLS13SigningError) -> ContiguousArray<UInt8> {
        switch storage {
        case .ed25519(let key):
            do {
                return try key.sign(message: message)
            } catch let error {
                throw .crypto(error)
            }
        case .p256(let key):
            var digest = ContiguousArray<UInt8>(
                repeating: 0,
                count: SHA256.digestByteCount
            )
            var destination = digest.mutableSpan
            do {
                try SHA256.hash(message, into: &destination)
                let rawSignature = try P256ECDSA.sign(
                    messageHash: digest.span,
                    using: key
                )
                return try TLS13ECDSASignatureCodec.encodeP256(
                    rawSignature.span
                )
            } catch let error {
                throw .crypto(error)
            }
        case .rsaPSS(let key):
            var digest = ContiguousArray<UInt8>(
                repeating: 0,
                count: SHA256.digestByteCount
            )
            var destination = digest.mutableSpan
            do {
                try SHA256.hash(message, into: &destination)
            } catch let error {
                throw .crypto(error)
            }
            do {
                return try RSAPSS.sign(
                    messageHash: digest.span,
                    using: key,
                    hash: .sha256
                )
            } catch let error {
                throw .rsa(error)
            }
        }
    }

    private static func copyBytes(
        _ bytes: Span<UInt8>
    ) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }
}
