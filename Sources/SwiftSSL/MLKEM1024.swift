import SwiftSSLCrypto

/// FIPS 203 ML-KEM-1024 exposed through SwiftSSL-owned key and result types.
public enum MLKEM1024: InPlaceKeyEncapsulationMechanism {
    public static let encapsulationByteCount = Encapsulation.byteCount
    public static let sharedSecretByteCount = SharedSecret.byteCount

    public struct PublicKey: Sendable, Equatable {
        public static let byteCount = SwiftSSLCrypto.MLKEM1024.PublicKey.byteCount
        fileprivate let implementation: SwiftSSLCrypto.MLKEM1024.PublicKey

        public init(bytes: Span<UInt8>) throws(KEMError) {
            do {
                implementation = try SwiftSSLCrypto.MLKEM1024.PublicKey(bytes: bytes)
            } catch {
                throw KEMError(error)
            }
        }

        fileprivate init(implementation: SwiftSSLCrypto.MLKEM1024.PublicKey) {
            self.implementation = implementation
        }

        public var span: Span<UInt8> { implementation.span }

        public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
            _ body: (Span<UInt8>) throws(Failure) -> Result
        ) throws(Failure) -> Result {
            try implementation.withBorrowedBytes(body)
        }
    }

    public struct PrivateKey: ~Copyable, Sendable {
        public static let byteCount = SwiftSSLCrypto.MLKEM1024.PrivateKey.byteCount
        fileprivate let implementation: SwiftSSLCrypto.MLKEM1024.PrivateKey

        public init(bytes: Span<UInt8>) throws(KEMError) {
            do {
                implementation = try SwiftSSLCrypto.MLKEM1024.PrivateKey(bytes: bytes)
            } catch {
                throw KEMError(error)
            }
        }

        fileprivate init(implementation: consuming SwiftSSLCrypto.MLKEM1024.PrivateKey) {
            self.implementation = implementation
        }

        public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
            _ body: (Span<UInt8>) throws(Failure) -> Result
        ) throws(Failure) -> Result {
            try implementation.withBorrowedBytes(body)
        }
    }

    public struct Encapsulation: Sendable, Equatable {
        public static let byteCount = SwiftSSLCrypto.MLKEM1024.Encapsulation.byteCount
        fileprivate let implementation: SwiftSSLCrypto.MLKEM1024.Encapsulation

        public init(bytes: Span<UInt8>) throws(KEMError) {
            do {
                implementation = try SwiftSSLCrypto.MLKEM1024.Encapsulation(bytes: bytes)
            } catch {
                throw KEMError(error)
            }
        }

        fileprivate init(implementation: SwiftSSLCrypto.MLKEM1024.Encapsulation) {
            self.implementation = implementation
        }

        public var span: Span<UInt8> { implementation.span }

        public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
            _ body: (Span<UInt8>) throws(Failure) -> Result
        ) throws(Failure) -> Result {
            try implementation.withBorrowedBytes(body)
        }
    }

    public struct SharedSecret: ~Copyable, Sendable {
        public static let byteCount = SwiftSSLCrypto.MLKEM1024.SharedSecret.byteCount
        fileprivate let implementation: SwiftSSLCrypto.MLKEM1024.SharedSecret

        fileprivate init(implementation: consuming SwiftSSLCrypto.MLKEM1024.SharedSecret) {
            self.implementation = implementation
        }

        public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
            _ body: (Span<UInt8>) throws(Failure) -> Result
        ) throws(Failure) -> Result {
            try implementation.withBorrowedBytes(body)
        }
    }

    public static func generateKeyPair(
        using entropy: borrowing any EntropySource
    ) throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
        let pair: SwiftSSLCrypto.KEMKeyPair<
            SwiftSSLCrypto.MLKEM1024.PublicKey,
            SwiftSSLCrypto.MLKEM1024.PrivateKey
        >
        do {
            pair = try SwiftSSLCrypto.MLKEM1024.generateKeyPair(using: entropy)
        } catch {
            throw KEMError(error)
        }
        return KEMKeyPair(
            publicKey: PublicKey(implementation: pair.publicKey),
            privateKey: PrivateKey(implementation: pair.privateKey)
        )
    }

    public static func generateKeyPair() throws(KEMError) -> KEMKeyPair<PublicKey, PrivateKey> {
        let pair: SwiftSSLCrypto.KEMKeyPair<
            SwiftSSLCrypto.MLKEM1024.PublicKey,
            SwiftSSLCrypto.MLKEM1024.PrivateKey
        >
        do {
            pair = try SwiftSSLCrypto.MLKEM1024.generateKeyPair()
        } catch {
            throw KEMError(error)
        }
        return KEMKeyPair(
            publicKey: PublicKey(implementation: pair.publicKey),
            privateKey: PrivateKey(implementation: pair.privateKey)
        )
    }

    public static func encapsulate(
        to publicKey: borrowing PublicKey,
        using entropy: borrowing any EntropySource
    ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
        let result: SwiftSSLCrypto.EncapsulationResult<
            SwiftSSLCrypto.MLKEM1024.Encapsulation,
            SwiftSSLCrypto.MLKEM1024.SharedSecret
        >
        do {
            result = try SwiftSSLCrypto.MLKEM1024.encapsulate(
                to: publicKey.implementation,
                using: entropy
            )
        } catch {
            throw KEMError(error)
        }
        return EncapsulationResult(
            encapsulation: Encapsulation(implementation: result.encapsulation),
            sharedSecret: SharedSecret(implementation: result.sharedSecret)
        )
    }

    public static func encapsulate(
        to publicKey: borrowing PublicKey
    ) throws(KEMError) -> EncapsulationResult<Encapsulation, SharedSecret> {
        let result: SwiftSSLCrypto.EncapsulationResult<
            SwiftSSLCrypto.MLKEM1024.Encapsulation,
            SwiftSSLCrypto.MLKEM1024.SharedSecret
        >
        do {
            result = try SwiftSSLCrypto.MLKEM1024.encapsulate(to: publicKey.implementation)
        } catch {
            throw KEMError(error)
        }
        return EncapsulationResult(
            encapsulation: Encapsulation(implementation: result.encapsulation),
            sharedSecret: SharedSecret(implementation: result.sharedSecret)
        )
    }

    public static func encapsulate(
        to publicKey: borrowing PublicKey,
        using entropy: borrowing any EntropySource,
        into encapsulation: inout MutableSpan<UInt8>,
        sharedSecret: inout MutableSpan<UInt8>
    ) throws(KEMError) {
        do {
            try SwiftSSLCrypto.MLKEM1024.encapsulate(
                to: publicKey.implementation,
                using: entropy,
                into: &encapsulation,
                sharedSecret: &sharedSecret
            )
        } catch {
            throw KEMError(error)
        }
    }

    public static func encapsulate(
        to publicKey: borrowing PublicKey,
        into encapsulation: inout MutableSpan<UInt8>,
        sharedSecret: inout MutableSpan<UInt8>
    ) throws(KEMError) {
        do {
            try SwiftSSLCrypto.MLKEM1024.encapsulate(
                to: publicKey.implementation,
                into: &encapsulation,
                sharedSecret: &sharedSecret
            )
        } catch {
            throw KEMError(error)
        }
    }

    public static func decapsulate(
        _ encapsulation: borrowing Encapsulation,
        using privateKey: borrowing PrivateKey
    ) throws(KEMError) -> SharedSecret {
        do {
            return SharedSecret(
                implementation: try SwiftSSLCrypto.MLKEM1024.decapsulate(
                    encapsulation.implementation,
                    using: privateKey.implementation
                )
            )
        } catch {
            throw KEMError(error)
        }
    }

    public static func decapsulate(
        _ encapsulation: Span<UInt8>,
        using privateKey: borrowing PrivateKey,
        into sharedSecret: inout MutableSpan<UInt8>
    ) throws(KEMError) {
        do {
            try SwiftSSLCrypto.MLKEM1024.decapsulate(
                encapsulation,
                using: privateKey.implementation,
                into: &sharedSecret
            )
        } catch {
            throw KEMError(error)
        }
    }
}
