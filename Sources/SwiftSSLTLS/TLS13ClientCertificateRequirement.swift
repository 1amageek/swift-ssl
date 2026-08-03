/// Whether the main handshake may continue without a client certificate.
public enum TLS13ClientCertificateRequirement: Sendable, Hashable {
  case optional
  case required
}
