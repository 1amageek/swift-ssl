public enum TLSCipherSuite: UInt16, Sendable, CaseIterable {
  case aes128GCM_SHA256 = 0x1301
  case aes256GCM_SHA384 = 0x1302
  case chacha20Poly1305_SHA256 = 0x1303
}
