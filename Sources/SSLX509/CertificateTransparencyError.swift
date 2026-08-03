import SSLCore

public enum CertificateTransparencyError: Error, Sendable, Equatable {
    case byte(ByteError)
    case invalidListLength
    case emptyList
    case tooManySCTs(limit: Int)
    case invalidSCT
    case missingEmbeddedSCTExtension
    case criticalEmbeddedSCTExtension
    case invalidEmbeddedSCTExtension
    case invalidPrecertificate
    case invalidIssuerKey
    case unsupportedVersion(UInt8)
    case unsupportedSignatureAlgorithm(hash: UInt8, signature: UInt8)
    case invalidLogIdentifier
    case duplicateLogIdentifier
    case timestampOutOfRange
    case signedDataTooLarge
    case signature(X509SignatureVerificationError)
    case insufficientValidSCTs(required: Int, actual: Int)
    case insufficientDistinctOperators(required: Int, actual: Int)
}
