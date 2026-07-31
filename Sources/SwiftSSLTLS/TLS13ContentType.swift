public enum TLS13ContentType: UInt8, Sendable, Hashable {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
}
