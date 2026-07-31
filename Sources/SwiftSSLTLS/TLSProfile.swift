package protocol TLSProfile: Sendable {
    associatedtype InboundChannel: Sendable, Hashable
    associatedtype Action: TLSBatchAction

    static var usesTLSRecords: Bool { get }
    static var usesDatagramReliability: Bool { get }
}
