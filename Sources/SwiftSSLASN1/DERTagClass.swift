public enum DERTagClass: UInt8, Sendable, Hashable {
    case universal = 0
    case application = 1
    case contextSpecific = 2
    case `private` = 3
}
