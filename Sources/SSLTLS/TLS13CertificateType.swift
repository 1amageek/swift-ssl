/// Authentication object encoding negotiated for a TLS 1.3 Certificate message.
public enum TLS13CertificateType: UInt8, Sendable, Hashable {
  case x509 = 0
  case rawPublicKey = 2

  package static let clientExtensionType: UInt16 = 19
  package static let serverExtensionType: UInt16 = 20
}
