import SwiftSSLCore

public enum DERWriteError: Error, Sendable, Equatable {
    case invalidTag
    case invalidLength
    case capacity(ByteError)
}
