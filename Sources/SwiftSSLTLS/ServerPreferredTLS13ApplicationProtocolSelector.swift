/// Selects the first server-preferred ALPN identifier offered by the client.
public struct ServerPreferredTLS13ApplicationProtocolSelector:
  TLS13ApplicationProtocolSelecting,
  Sendable
{
  private let supportedProtocols: ContiguousArray<TLS13ApplicationProtocol>

  public init(
    supportedProtocols: consuming ContiguousArray<TLS13ApplicationProtocol>
  ) throws(TLS13ApplicationProtocolError) {
    guard !supportedProtocols.isEmpty else {
      throw .noApplicationProtocol
    }
    var index = 0
    while index < supportedProtocols.count {
      var comparisonIndex = index + 1
      while comparisonIndex < supportedProtocols.count {
        guard supportedProtocols[index] != supportedProtocols[comparisonIndex]
        else {
          throw .duplicateIdentifier
        }
        comparisonIndex += 1
      }
      index += 1
    }
    self.supportedProtocols = supportedProtocols
  }

  public func select(
    from offeredProtocols: borrowing ContiguousArray<TLS13ApplicationProtocol>
  ) throws(TLS13ApplicationProtocolError) -> TLS13ApplicationProtocol {
    var supportedIndex = 0
    while supportedIndex < supportedProtocols.count {
      var offeredIndex = 0
      while offeredIndex < offeredProtocols.count {
        if supportedProtocols[supportedIndex] == offeredProtocols[offeredIndex] {
          return supportedProtocols[supportedIndex]
        }
        offeredIndex += 1
      }
      supportedIndex += 1
    }
    throw .noApplicationProtocol
  }
}
