import SwiftSSLASN1

public extension PrivateKeyInfo {
    /// Parses the RFC 5915 payload carried by an EC PKCS #8 private key.
    ///
    /// The outer algorithm identifier supplies the required named curve. The
    /// inner parser must agree with it; a missing or mismatched curve is a
    /// typed failure and is never inferred from scalar length alone.
    borrowing func ecPrivateKey() throws(ECPrivateKeyError) -> ECPrivateKey {
        guard case let .ecPublicKey(curve) = algorithm else {
            throw .invalidParameters
        }
        return try withPrivateKeyBytes { (bytes: Span<UInt8>) throws(ECPrivateKeyError) -> ECPrivateKey in
            try ECPrivateKey(der: bytes, expectedCurve: curve)
        }
    }
}
