import SwiftSSLCore
import SwiftSSLASN1

/// A decrypted PKCS #12 identity whose private key is uniquely owned and wiped.
public struct PKCS12Identity: ~Copyable, Sendable {
    public let certificateCount: Int
    public let privateKeyAlgorithm: PublicKeyAlgorithm

    private let privateKey: PrivateKeyInfo
    private let certificates: ContiguousArray<CertificateBytes>

    init(
        privateKey: consuming PrivateKeyInfo,
        certificates: consuming ContiguousArray<CertificateBytes>
    ) {
        privateKeyAlgorithm = privateKey.algorithm
        certificateCount = certificates.count
        self.privateKey = privateKey
        self.certificates = certificates
    }

    public borrowing func withPrivateKeyDER<
        Result: ~Copyable,
        Failure: Error
    >(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try privateKey.withDERBytes(body)
    }

    public borrowing func certificate(at index: Int) throws
        -> CertificateBytes
    {
        guard certificates.indices.contains(index) else {
            throw PKCS12ArchiveError.certificateIndexOutOfBounds(
                index: index,
                count: certificates.count
            )
        }
        return certificates[index]
    }

    public consuming func takePrivateKey() -> PrivateKeyInfo {
        privateKey
    }
}
