import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLX509

/// A validated public-key capability used only for TLS CertificateVerify.
enum TLS13CertificateVerificationKey: Sendable {
  case ed25519(Ed25519PublicKey)
  case p256(P256PublicKey)
  case rsaPSS(RSAPublicKey)

  init(
    subjectPublicKeyInfo: SubjectPublicKeyInfo
  ) throws(CryptoInputError) {
    if subjectPublicKeyInfo.isEd25519 {
      self = try subjectPublicKeyInfo.withPublicKeyBytes {
        bytes throws(CryptoInputError) -> TLS13CertificateVerificationKey in
        .ed25519(try Ed25519PublicKey(bytes: bytes))
      }
    } else if subjectPublicKeyInfo.isP256 {
      self = try subjectPublicKeyInfo.withPublicKeyBytes {
        bytes throws(CryptoInputError) -> TLS13CertificateVerificationKey in
        .p256(try P256PublicKey(bytes: bytes))
      }
    } else if subjectPublicKeyInfo.isRSA {
      self = try subjectPublicKeyInfo.withPublicKeyBytes {
        bytes throws(CryptoInputError) -> TLS13CertificateVerificationKey in
        .rsaPSS(try RSAPublicKey(pkcs1DER: bytes))
      }
    } else {
      throw .invalidPeerKey
    }
  }

  var signatureScheme: TLS13SignatureScheme {
    switch self {
    case .ed25519:
      return .ed25519
    case .p256:
      return .ecdsaP256SHA256
    case .rsaPSS:
      return .rsaPSSRSAESHA256
    }
  }

  func verify(
    _ value: TLS13CertificateVerify,
    signedMessage: Span<UInt8>
  ) throws(CryptoInputError) -> Bool {
    guard value.signatureScheme == signatureScheme else {
      return false
    }
    switch self {
    case .ed25519(let publicKey):
      return try Ed25519.verify(
        signature: value.signature.span,
        message: signedMessage,
        using: publicKey
      )
    case .p256(let publicKey):
      let rawSignature = try TLS13ECDSASignatureCodec.decodeP256(
        value.signature.span
      )
      var digest = ContiguousArray<UInt8>(
        repeating: 0,
        count: SHA256.digestByteCount
      )
      var destination = digest.mutableSpan
      try SHA256.hash(signedMessage, into: &destination)
      return try P256ECDSA.verify(
        signature: rawSignature.span,
        messageHash: digest.span,
        using: publicKey
      )
    case .rsaPSS(let publicKey):
      var digest = ContiguousArray<UInt8>(
        repeating: 0,
        count: SHA256.digestByteCount
      )
      var destination = digest.mutableSpan
      try SHA256.hash(signedMessage, into: &destination)
      return try RSAPSS.verify(
        signature: value.signature.span,
        messageHash: digest.span,
        publicKey: publicKey,
        hash: .sha256,
        saltLength: SHA256.digestByteCount
      )
    }
  }
}
