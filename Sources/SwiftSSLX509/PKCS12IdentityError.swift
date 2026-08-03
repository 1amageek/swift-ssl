import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLASN1

public enum PKCS12IdentityError: Error, Sendable, Equatable {
    case archive(PKCS12ArchiveError)
    case encryption(PBES2AES256GCMError)
    case unsupportedPrivateKeyAlgorithm
    case unsupportedCertificatePublicKeyAlgorithm
    case malformedEd25519PrivateKey
    case keyPairMismatch
    case certificate(X509CertificateError)
    case der(DERError)
    case resourceLimit(ResourceLimitError)
    case cryptographicInput(CryptoInputError)
}
