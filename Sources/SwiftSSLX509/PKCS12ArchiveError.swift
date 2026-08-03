import SwiftSSLCore
import SwiftSSLASN1

public enum PKCS12ArchiveError: Error, Sendable, Equatable {
    case invalidStructure
    case invalidVersion(UInt64)
    case unsupportedContentType
    case unsupportedAuthenticatedSafeContent
    case multipleSafeContents
    case macDataUnsupported
    case missingEncryptedPrivateKey
    case multipleEncryptedPrivateKeys
    case missingCertificates
    case unsupportedBagType
    case bagAttributesUnsupported
    case unsupportedCertificateType
    case certificateIndexOutOfBounds(index: Int, count: Int)
    case sizeOverflow
    case der(DERError)
    case value(DERValueError)
    case write(DERWriteError)
    case resourceLimit(ResourceLimitError)
    case invalidRange(ByteError)
    case encryptedPrivateKey(EncryptedPrivateKeyInfoError)
    case certificate(X509CertificateError)
}
