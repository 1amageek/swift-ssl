import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

/// Private signing material selected by the TLS 1.3 authentication profile.
///
/// The enum is noncopyable because its cases own noncopyable secret keys. It
/// keeps protocol selection explicit and prevents a certificate/key mismatch
/// from being hidden behind an untyped callback.
// FIXME(INCOMPLETE_IMPLEMENTATION): The NIST ECDSA cases are connected to the
// TLS CertificateVerify wire path, but their variable-time arithmetic still
// requires constant-time, differential, sanitizer, and performance release
// evidence before this authentication profile can be release-qualified.
public enum TLS13SigningKey: ~Copyable, Sendable {
    case ed25519(Ed25519PrivateKey)
    case p256(P256PrivateKey)
    case p384(P384PrivateKey)
    case p521(P521PrivateKey)

    /// Builds a TLS signing owner from a parsed RFC 5915 ECPrivateKey.
    ///
    /// The outer PKCS #8 curve and the inner RFC 5915 curve have already been
    /// matched by `PrivateKeyInfo.ecPrivateKey()`. If the optional public
    /// field is present, it must also equal the public point derived from the
    /// scalar before the key becomes selectable by the handshake.
    public static func fromECPrivateKey(
        _ privateKey: borrowing ECPrivateKey
    ) throws(CryptoInputError) -> TLS13SigningKey {
        switch privateKey.curve {
        case .prime256v1:
            let key: P256PrivateKey = try privateKey.withPrivateKeyBytes {
                (bytes: Span<UInt8>) throws(CryptoInputError) -> P256PrivateKey in
                try P256PrivateKey(bytes: bytes)
            }
            guard matches(privateKey.publicKey, key.publicKey().span) else {
                throw .invalidPeerKey
            }
            return .p256(key)

        case .secp384r1:
            let key: P384PrivateKey = try privateKey.withPrivateKeyBytes {
                (bytes: Span<UInt8>) throws(CryptoInputError) -> P384PrivateKey in
                try P384PrivateKey(bytes: bytes)
            }
            guard matches(privateKey.publicKey, key.publicKey().span) else {
                throw .invalidPeerKey
            }
            return .p384(key)

        case .secp521r1:
            let key: P521PrivateKey = try privateKey.withPrivateKeyBytes {
                (bytes: Span<UInt8>) throws(CryptoInputError) -> P521PrivateKey in
                try P521PrivateKey(bytes: bytes)
            }
            guard matches(privateKey.publicKey, key.publicKey().span) else {
                throw .invalidPeerKey
            }
            return .p521(key)

        case .unknown:
            throw .invalidPeerKey
        }
    }

    public var signatureScheme: TLS13SignatureScheme {
        switch self {
        case .ed25519: return .ed25519
        case .p256: return .ecdsaP256SHA256
        case .p384: return .ecdsaP384SHA384
        case .p521: return .ecdsaP521SHA512
        }
    }

    public borrowing func publicKeyBytes() throws(CryptoInputError) -> ContiguousArray<UInt8> {
        switch self {
        case .ed25519(let key):
            return try key.publicKey()
        case .p256(let key):
            return copyBytes(key.publicKey().span)
        case .p384(let key):
            return copyBytes(key.publicKey().span)
        case .p521(let key):
            return copyBytes(key.publicKey().span)
        }
    }

    public borrowing func sign(
        message: Span<UInt8>
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        switch self {
        case .ed25519(let key):
            return try key.sign(message: message)
        case .p256(let key):
            var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA256.digestByteCount)
            var destination = digest.mutableSpan
            try SHA256.hash(message, into: &destination)
            return try P256ECDSA.sign(messageHash: digest.span, privateKey: key)
        case .p384(let key):
            var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA384.digestByteCount)
            var destination = digest.mutableSpan
            try SHA384.hash(message, into: &destination)
            return try P384ECDSA.sign(messageHash: digest.span, privateKey: key)
        case .p521(let key):
            var digest = ContiguousArray<UInt8>(repeating: 0, count: SHA512.digestByteCount)
            var destination = digest.mutableSpan
            try SHA512.hash(message, into: &destination)
            return try P521ECDSA.sign(messageHash: digest.span, privateKey: key)
        }
    }

    private func copyBytes(_ bytes: Span<UInt8>) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }

    private static func matches(_ expected: OwnedBytes?, _ actual: Span<UInt8>) -> Bool {
        guard let expected else { return true }
        guard expected.count == actual.count else { return false }
        var index = 0
        while index < actual.count {
            guard expected[index] == actual[index] else { return false }
            index += 1
        }
        return true
    }
}
