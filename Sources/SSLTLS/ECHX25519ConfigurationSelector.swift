import SSLCrypto

/// RFC 9849 selection for the package's X25519 HPKE profile.
public struct ECHX25519ConfigurationSelector: ECHConfigurationSelecting, Sendable {
  private let supportedCipherSuites: ContiguousArray<ECHCipherSuite>

  public init(
    supportedCipherSuites: consuming ContiguousArray<ECHCipherSuite> = [
      ECHCipherSuite(kdf: .sha256, aead: .aes128GCM),
      ECHCipherSuite(kdf: .sha256, aead: .chaCha20Poly1305),
      ECHCipherSuite(kdf: .sha256, aead: .aes256GCM),
    ]
  ) {
    self.supportedCipherSuites = supportedCipherSuites
  }

  public func selectConfiguration(
    from list: ECHConfigList
  ) throws(ECHError) -> ECHSelectedConfig {
    for config in list.configurations where config.isUsableByX25519Profile {
      for suite in config.cipherSuites where supportedCipherSuites.contains(suite) {
        return ECHSelectedConfig(config: config, cipherSuite: suite)
      }
    }
    throw .noCompatibleConfiguration
  }
}
