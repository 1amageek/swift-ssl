public protocol TLS13ApplicationProtocolSelecting: Sendable {
  func select(
    from offeredProtocols: borrowing ContiguousArray<TLS13ApplicationProtocol>
  ) throws(TLS13ApplicationProtocolError) -> TLS13ApplicationProtocol
}
