import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

extension TLS13DelegatedCredential {
  /// Issues a delegated credential using the leaf certificate signing key.
  public static func issue(
    validTime: UInt32,
    certificateVerifyAlgorithm: TLS13SignatureScheme,
    subjectPublicKeyInfoDER: Span<UInt8>,
    certificate: X509Certificate,
    role: TLSRole,
    certificateSigningKey: borrowing TLS13SigningKey,
    at instant: VerificationInstant
  ) throws(TLS13DelegatedCredentialError) -> TLS13DelegatedCredential {
    let codec = RFC9345TLS13DelegatedCredentialCodec()
    let signingInput: OwnedBytes
    do {
      signingInput = try certificate.withDERBytes {
        certificateDER throws(TLS13DelegatedCredentialError) in
        try codec.makeSigningInput(
          validTime: validTime,
          certificateVerifyAlgorithm: certificateVerifyAlgorithm,
          subjectPublicKeyInfoDER: subjectPublicKeyInfoDER,
          delegationAlgorithm: certificateSigningKey.signatureScheme,
          role: role,
          certificateDER: certificateDER
        )
      }
    } catch let error {
      throw error
    }
    let signature: ContiguousArray<UInt8>
    do {
      signature = try certificateSigningKey.sign(message: signingInput.span)
    } catch let error {
      throw .signing(error)
    }
    let delegatedCredential = try TLS13DelegatedCredential(
      validTime: validTime,
      certificateVerifyAlgorithm: certificateVerifyAlgorithm,
      subjectPublicKeyInfoDER: subjectPublicKeyInfoDER,
      delegationAlgorithm: certificateSigningKey.signatureScheme,
      signature: signature.span
    )
    let validator = RFC9345TLS13DelegatedCredentialValidator()
    _ = try validator.validate(
      delegatedCredential,
      certificate: certificate,
      role: role,
      signatureSchemes: [certificateSigningKey.signatureScheme],
      delegatedCredentialAlgorithms: [certificateVerifyAlgorithm],
      at: instant
    )
    return delegatedCredential
  }
}
