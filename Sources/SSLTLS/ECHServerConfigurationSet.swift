/// An immutable set of active ECH decryption keys and advertised retry configs.
public struct ECHServerConfigurationSet: Sendable {
  public let configurations: ContiguousArray<ECHServerConfiguration>
  public let retryConfigurations: ECHConfigList?

  public init(
    configurations: ContiguousArray<ECHServerConfiguration>
  ) throws(ECHError) {
    guard !configurations.isEmpty else { throw .malformedConfigList }
    var retry = ContiguousArray<ECHConfig>()
    retry.reserveCapacity(configurations.count)
    for configuration in configurations where configuration.isRetryConfiguration {
      retry.append(configuration.config)
    }
    let encodedRetry: ECHConfigList?
    if retry.isEmpty {
      encodedRetry = nil
    } else {
      encodedRetry = try ECHConfigList(configurations: retry)
    }
    self.configurations = configurations
    retryConfigurations = encodedRetry
  }
}
