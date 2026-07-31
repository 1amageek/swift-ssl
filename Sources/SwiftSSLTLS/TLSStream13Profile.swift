public enum TLSStream13Profile: TLSProfile {
    public typealias InboundChannel = TLSStreamChannel
    public typealias Action = TLSStreamAction

    public static let usesTLSRecords = true
    public static let usesDatagramReliability = false
}
