import SSLTLS

public enum QUICTLSHandshakeStreamError: Error, Sendable, Equatable {
    case incompatibleLimits(
        maximumBufferedByteCount: Int,
        maximumMessageByteCount: Int
    )
    case reassembly(QUICCryptoStreamError)
    case framing(TLSHandshakeMessageFramingError)
    case incompleteMessage(minimumAdditionalByteCount: Int)
}
