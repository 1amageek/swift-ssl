/// Supported TLS-family protocol versions at the vocabulary boundary.
public enum TLSVersion: UInt16, Sendable, Hashable, CaseIterable {
    case tls13 = 0x0304
}
