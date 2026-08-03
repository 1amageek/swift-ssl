public enum TLS13HandshakeEncoding: Sendable, Hashable {
  case tls13
  case quic
  case dtls13

  package var legacyVersion: UInt16 {
    switch self {
    case .tls13, .quic: 0x0303
    case .dtls13: 0xFEFD
    }
  }

  package var includesLegacyCookie: Bool {
    self == .dtls13
  }

  package var negotiatedVersion: UInt16 {
    switch self {
    case .tls13, .quic: 0x0304
    case .dtls13: 0xFEFC
    }
  }
}
