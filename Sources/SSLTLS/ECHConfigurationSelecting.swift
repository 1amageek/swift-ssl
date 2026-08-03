/// Selects one usable ECH configuration without performing I/O or fallback.
public protocol ECHConfigurationSelecting: Sendable {
  func selectConfiguration(
    from list: ECHConfigList
  ) throws(ECHError) -> ECHSelectedConfig
}
