import SSLTLS

public enum QUICTLSProfile: TLSProfile {
    public typealias InboundChannel = QUICHandshakeEncryptionLevel
    public typealias Action = QUICTLSAction

    public static let usesTLSRecords = false
    public static let usesDatagramReliability = false
}
