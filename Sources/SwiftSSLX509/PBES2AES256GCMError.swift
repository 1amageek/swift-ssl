import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLASN1

public enum PBES2AES256GCMError: Error, Sendable, Equatable {
    case emptyPassword
    case invalidConfiguration(
        minimum: UInt32,
        maximum: UInt32,
        encryptionIterations: UInt32
    )
    case iterationCountOutOfPolicy(
        minimum: UInt32,
        maximum: UInt32,
        actual: UInt32
    )
    case sizeOverflow
    case entropy(EntropyError)
    case keyDerivation(PBKDF2Error)
    case authenticatedCipher(AEADError)
    case authenticationFailed
    case secretMemory(SecretMemoryError)
    case format(EncryptedPrivateKeyInfoError)
    case privateKey(PrivateKeyInfoError)
    case derWrite(DERWriteError)
}
