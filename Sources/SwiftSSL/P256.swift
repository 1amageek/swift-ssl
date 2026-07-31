import SwiftSSLCore
import SwiftSSLCrypto

/// NIST P-256 ECDH key agreement exposed by the SwiftSSL façade.
// FIXME(INCOMPLETE_IMPLEMENTATION): The façade is vector-tested and
// target-validated, but the underlying variable-time arithmetic still needs
// constant-time and differential release gates before protocol selection.
public enum P256 {
    public static func sharedSecret(
        privateKey: borrowing P256PrivateKey,
        peerPublicKey: borrowing P256PublicKey
    ) throws(CryptoInputError) -> P256SharedSecret {
        do {
            let implementation = try SwiftSSLCrypto.P256.sharedSecret(
                privateKey: privateKey.implementation,
                peerPublicKey: peerPublicKey.implementation
            )
            return P256SharedSecret(implementation: implementation)
        } catch {
            throw CryptoInputError(error)
        }
    }
}

/// P-256 ECDSA signing and verification exposed by the SwiftSSL façade.
// FIXME(INCOMPLETE_IMPLEMENTATION): This façade exposes a validation path for
// P-256 ECDSA, but protocol authentication must remain on the Ed25519 profile
// until constant-time, differential, sanitizer, and performance gates pass.
public enum P256ECDSA {
    public static let signatureByteCount = SwiftSSLCrypto.P256ECDSA.signatureByteCount

    public static func sign(
        messageHash: Span<UInt8>,
        privateKey: borrowing P256PrivateKey
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        do {
            return try SwiftSSLCrypto.P256ECDSA.sign(
                messageHash: messageHash,
                privateKey: privateKey.implementation
            )
        } catch {
            throw CryptoInputError(error)
        }
    }

    public static func verify(
        signature: Span<UInt8>,
        messageHash: Span<UInt8>,
        publicKey: borrowing P256PublicKey
    ) throws(CryptoInputError) -> Bool {
        do {
            return try SwiftSSLCrypto.P256ECDSA.verify(
                signature: signature,
                messageHash: messageHash,
                publicKey: publicKey.implementation
            )
        } catch {
            throw CryptoInputError(error)
        }
    }
}

public struct P256PrivateKey: ~Copyable, Sendable {
    public static let byteCount = SwiftSSLCrypto.P256PrivateKey.byteCount
    fileprivate let implementation: SwiftSSLCrypto.P256PrivateKey

    public static func generate(
        using entropy: borrowing any EntropySource
    ) throws(P256KeyGenerationError) -> P256PrivateKey {
        do {
            return P256PrivateKey(
                implementation: try SwiftSSLCrypto.P256PrivateKey.generate(using: entropy)
            )
        } catch let error {
            switch error {
            case .entropy(let value): throw .entropy(value)
            case .memoryFailure: throw .memoryFailure
            case .invalidScalar: throw .invalidScalar
            }
        }
    }

    public static func generate() throws(P256KeyGenerationError) -> P256PrivateKey {
        do {
            return P256PrivateKey(
                implementation: try SwiftSSLCrypto.P256PrivateKey.generate()
            )
        } catch let error {
            switch error {
            case .entropy(let value): throw .entropy(value)
            case .memoryFailure: throw .memoryFailure
            case .invalidScalar: throw .invalidScalar
            }
        }
    }

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        do {
            implementation = try SwiftSSLCrypto.P256PrivateKey(bytes: bytes)
        } catch {
            throw CryptoInputError(error)
        }
    }

    fileprivate init(implementation: consuming SwiftSSLCrypto.P256PrivateKey) {
        self.implementation = implementation
    }

    public borrowing func publicKey() -> P256PublicKey {
        P256PublicKey(implementation: implementation.publicKey())
    }
}

public struct P256PublicKey: Sendable, Equatable {
    public static let uncompressedByteCount = SwiftSSLCrypto.P256PublicKey.uncompressedByteCount
    fileprivate let implementation: SwiftSSLCrypto.P256PublicKey

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        do {
            implementation = try SwiftSSLCrypto.P256PublicKey(bytes: bytes)
        } catch {
            throw CryptoInputError(error)
        }
    }

    fileprivate init(implementation: SwiftSSLCrypto.P256PublicKey) {
        self.implementation = implementation
    }

    public var span: Span<UInt8> { implementation.span }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try implementation.withBorrowedBytes(body)
    }
}

public struct P256SharedSecret: ~Copyable, Sendable {
    public static let byteCount = SwiftSSLCrypto.P256SharedSecret.byteCount
    private let implementation: SwiftSSLCrypto.P256SharedSecret

    fileprivate init(implementation: consuming SwiftSSLCrypto.P256SharedSecret) {
        self.implementation = implementation
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try implementation.withBorrowedBytes(body)
    }
}

public enum P256KeyGenerationError: Error, Sendable, Equatable {
    case entropy(EntropyError)
    case memoryFailure
    case invalidScalar
}
