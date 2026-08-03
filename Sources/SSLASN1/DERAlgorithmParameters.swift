public enum DERAlgorithmParameters: Sendable, Hashable {
    case absent
    case null
    case objectIdentifier(ContiguousArray<UInt64>)
    case other
}
