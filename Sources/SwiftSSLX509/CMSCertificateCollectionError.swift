import SwiftSSLCore
import SwiftSSLASN1

public enum CMSCertificateCollectionError: Error, Sendable, Equatable {
    case emptyCertificateCollection
    case certificateIndexOutOfBounds(index: Int, count: Int)
    case invalidStructure
    case invalidVersion(UInt64)
    case unsupportedContentType
    case unsupportedEncapsulatedContentType
    case nonEmptyDigestAlgorithms
    case missingCertificates
    case unsupportedCertificateChoice
    case nonCanonicalCertificateOrder
    case nonEmptySignerInfos
    case der(DERError)
    case value(DERValueError)
    case resourceLimit(ResourceLimitError)
    case invalidRange(ByteError)
    case certificate(X509CertificateError)
    case write(DERWriteError)
    case sizeOverflow
}
