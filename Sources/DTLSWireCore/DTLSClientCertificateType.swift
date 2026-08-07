/// A client certificate key capability advertised by a DTLS 1.2 server.
public enum DTLSClientCertificateType: UInt8, Sendable {
    case rsaSign = 1
    case ecdsaSign = 64
}
