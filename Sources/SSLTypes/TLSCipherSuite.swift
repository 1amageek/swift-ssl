/// TLS 1.3 cipher-suite identifiers shared by the protocol profiles.
///
/// The identifier is vocabulary, not an implementation of hashing or record
/// protection. `SSLCrypto` maps the selected value to concrete primitives at
/// the mechanism boundary.
public enum TLSCipherSuite: UInt16, Sendable, Hashable, CaseIterable {
    case aes128GCM_SHA256 = 0x1301
    case aes256GCM_SHA384 = 0x1302
    case chacha20Poly1305_SHA256 = 0x1303
}
