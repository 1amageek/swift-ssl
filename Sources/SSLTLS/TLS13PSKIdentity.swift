import SSLCore

public struct TLS13PSKIdentity: Sendable, Hashable {
    public static let maximumIdentityByteCount = 65_535

    public let identity: OwnedBytes
    public let obfuscatedTicketAge: UInt32

    public init(
        identity: Span<UInt8>,
        obfuscatedTicketAge: UInt32
    ) throws(TLS13PSKError) {
        guard !identity.isEmpty else { throw .emptyIdentity }
        guard identity.count <= Self.maximumIdentityByteCount else {
            throw .invalidIdentityLength(identity.count)
        }
        self.identity = OwnedBytes(copying: identity)
        self.obfuscatedTicketAge = obfuscatedTicketAge
    }
}
