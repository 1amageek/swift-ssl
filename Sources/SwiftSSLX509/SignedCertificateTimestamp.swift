import SwiftSSLCore

public struct SignedCertificateTimestamp: Sendable, Hashable {
    public let version: UInt8
    public let logIdentifier: OwnedBytes
    public let timestampMilliseconds: UInt64
    public let extensions: OwnedBytes
    public let hashAlgorithm: UInt8
    public let signatureAlgorithm: UInt8
    public let signature: OwnedBytes

    internal init(
        version: UInt8,
        logIdentifier: consuming OwnedBytes,
        timestampMilliseconds: UInt64,
        extensions: consuming OwnedBytes,
        hashAlgorithm: UInt8,
        signatureAlgorithm: UInt8,
        signature: consuming OwnedBytes
    ) {
        self.version = version
        self.logIdentifier = logIdentifier
        self.timestampMilliseconds = timestampMilliseconds
        self.extensions = extensions
        self.hashAlgorithm = hashAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}
