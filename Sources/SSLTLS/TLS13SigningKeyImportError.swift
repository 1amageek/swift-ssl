import SSLASN1
import SSLCrypto
import SSLX509

/// A typed failure while converting PKCS #8 material into a TLS signing key.
public enum TLS13SigningKeyImportError: Error, Sendable, Equatable {
    case unsupportedAlgorithm(PublicKeyAlgorithm)
    case invalidAlgorithmParameters
    case malformedPrivateKey
    case publicKeyMismatch
    case ec(ECPrivateKeyError)
    case rsa(RSAKeyError)
    case crypto(CryptoInputError)
}
