struct DTLS13CoreAdaptation: Sendable {
  let flight: DTLS13Flight?
  let terminalActions: ContiguousArray<DTLSAction>
}
