import SwiftSSLCore

public protocol TLS13DelegatedCredentialCoding: Sendable {
  func encode(
    _ delegatedCredential: TLS13DelegatedCredential
  ) throws(TLS13DelegatedCredentialError) -> OwnedBytes

  func decode(
    _ encoded: Span<UInt8>
  ) throws(TLS13DelegatedCredentialError) -> TLS13DelegatedCredential

  func makeSigningInput(
    validTime: UInt32,
    certificateVerifyAlgorithm: TLS13SignatureScheme,
    subjectPublicKeyInfoDER: Span<UInt8>,
    delegationAlgorithm: TLS13SignatureScheme,
    role: TLSRole,
    certificateDER: Span<UInt8>
  ) throws(TLS13DelegatedCredentialError) -> OwnedBytes
}
