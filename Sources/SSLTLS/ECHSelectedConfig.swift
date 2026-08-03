/// A selected configuration and its concrete HPKE symmetric suite.
public struct ECHSelectedConfig: Sendable, Hashable {
  public let config: ECHConfig
  public let cipherSuite: ECHCipherSuite

  public init(config: ECHConfig, cipherSuite: ECHCipherSuite) {
    self.config = config
    self.cipherSuite = cipherSuite
  }
}
