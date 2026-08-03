public enum DTLS13Profile: TLSProfile {
    public enum Channel: Sendable, Hashable {
        case datagram
    }

    public typealias InboundChannel = Channel
    public typealias Action = DTLSAction

    public static let usesTLSRecords = false
    public static let usesDatagramReliability = true
}
