import SwiftSSLCore
import SwiftSSLX509

/// One RFC 9345 DelegatedCredential carried by a leaf CertificateEntry.
public struct TLS13DelegatedCredential: Sendable, Hashable {
  public static let extensionType: UInt16 = 34

  public let validTime: UInt32
  public let certificateVerifyAlgorithm: TLS13SignatureScheme
  public let subjectPublicKeyInfo: SubjectPublicKeyInfo
  public let delegationAlgorithm: TLS13SignatureScheme
  public let signature: OwnedBytes

  public init(
    validTime: UInt32,
    certificateVerifyAlgorithm: TLS13SignatureScheme,
    subjectPublicKeyInfoDER: Span<UInt8>,
    delegationAlgorithm: TLS13SignatureScheme,
    signature: Span<UInt8>
  ) throws(TLS13DelegatedCredentialError) {
    guard !signature.isEmpty, signature.count <= Int(UInt16.max) else {
      throw .malformedCredential
    }
    let subjectPublicKeyInfo: SubjectPublicKeyInfo
    do {
      subjectPublicKeyInfo = try SubjectPublicKeyInfo(der: subjectPublicKeyInfoDER)
    } catch let error {
      throw .subjectPublicKeyInfo(error)
    }
    guard certificateVerifyAlgorithm == .ecdsaP256SHA256
      || certificateVerifyAlgorithm == .ed25519,
      certificateVerifyAlgorithm.matches(subjectPublicKeyInfo),
      !subjectPublicKeyInfo.isRSA
    else {
      throw .unsupportedCertificateVerifyAlgorithm
    }
    self.validTime = validTime
    self.certificateVerifyAlgorithm = certificateVerifyAlgorithm
    self.subjectPublicKeyInfo = subjectPublicKeyInfo
    self.delegationAlgorithm = delegationAlgorithm
    self.signature = OwnedBytes(copying: signature)
  }
}
