import SwiftSSLCore

public enum TLS13HandshakeCoreOutputError: Error, Sendable, Equatable {
    case byteRange(ByteError)
    case duplicateTrafficSecrets(TLS13HandshakeEpoch)
    case missingTrafficSecrets(TLS13HandshakeEpoch)
    case unreferencedTrafficSecrets(TLS13HandshakeEpoch)
}
