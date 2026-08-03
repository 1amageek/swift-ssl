import SwiftSSLCore

public enum DERWriteError: Error, Sendable, Equatable {
    case invalidTag
    case invalidLength
    case invalidObjectIdentifier
    case capacity(ByteError)
}
