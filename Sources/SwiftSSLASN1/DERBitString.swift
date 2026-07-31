import SwiftSSLCore

public struct DERBitString: Sendable, Equatable {
    public let unusedBitCount: UInt8
    public let bytes: OwnedBytes

    public init(unusedBitCount: UInt8, bytes: OwnedBytes) {
        self.unusedBitCount = unusedBitCount
        self.bytes = bytes
    }
}
