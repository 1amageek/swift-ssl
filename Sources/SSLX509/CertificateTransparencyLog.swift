import SSLCore
import SSLCrypto

public struct CertificateTransparencyLog: Sendable, Hashable {
    public let logIdentifier: OwnedBytes
    public let publicKey: SubjectPublicKeyInfo
    public let operatorIdentifier: UInt64
    public let validFrom: VerificationInstant
    public let validUntil: VerificationInstant

    public init(
        publicKey: SubjectPublicKeyInfo,
        operatorIdentifier: UInt64,
        validFrom: VerificationInstant,
        validUntil: VerificationInstant
    ) throws(CertificateTransparencyError) {
        guard validFrom <= validUntil else { throw .timestampOutOfRange }
        var digest = ContiguousArray<UInt8>(
            repeating: 0,
            count: SHA256.digestByteCount
        )
        do {
            try publicKey.withDERBytes {
                bytes throws(CryptoInputError) in
                var output = digest.mutableSpan
                try SHA256.hash(bytes, into: &output)
            }
        } catch {
            throw .invalidLogIdentifier
        }
        logIdentifier = OwnedBytes(consuming: digest)
        self.publicKey = publicKey
        self.operatorIdentifier = operatorIdentifier
        self.validFrom = validFrom
        self.validUntil = validUntil
    }

    public func isQualified(at instant: VerificationInstant) -> Bool {
        validFrom <= instant && instant <= validUntil
    }
}
