import SwiftSSLCore

public struct TLS13NewSessionTicket: Sendable, Hashable {
    public static let maximumLifetime: UInt32 = 604_800
    public static let maximumNonceByteCount = 255
    public static let maximumTicketByteCount = 65_535

    public let lifetime: UInt32
    public let ageAdd: UInt32
    public let ticketNonce: OwnedBytes
    public let ticket: OwnedBytes
    /// Raw extension list contents, excluding the two-byte vector length.
    public let extensions: OwnedBytes

    public init(
        lifetime: UInt32,
        ageAdd: UInt32,
        ticketNonce: Span<UInt8>,
        ticket: Span<UInt8>,
        extensions: Span<UInt8>
    ) throws(TLS13SessionTicketError) {
        guard lifetime > 0, lifetime <= Self.maximumLifetime else {
            throw .invalidLifetime(lifetime)
        }
        guard ticketNonce.count <= Self.maximumNonceByteCount else {
            throw .invalidNonceLength(ticketNonce.count)
        }
        guard !ticket.isEmpty, ticket.count <= Self.maximumTicketByteCount else {
            throw .invalidTicketLength(ticket.count)
        }
        try TLS13NewSessionTicket.validateExtensions(extensions)
        self.lifetime = lifetime
        self.ageAdd = ageAdd
        self.ticketNonce = OwnedBytes(copying: ticketNonce)
        self.ticket = OwnedBytes(copying: ticket)
        self.extensions = OwnedBytes(copying: extensions)
    }

    public borrowing func withTicketBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(ticket.span)
    }

    public borrowing func withExtensions<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(extensions.span)
    }

    static func validateExtensions(
        _ bytes: Span<UInt8>
    ) throws(TLS13SessionTicketError) {
        var cursor = ByteCursor(bytes)
        var seen = Set<UInt16>()
        do {
            while !cursor.isAtEnd {
                let type = try cursor.readUInt16BigEndian()
                let length = Int(try cursor.readUInt16BigEndian())
                _ = try cursor.readSpan(count: length)
                guard seen.insert(type).inserted else {
                    throw TLS13SessionTicketError.duplicateExtension(type)
                }
            }
        } catch let error as TLS13SessionTicketError {
            throw error
        } catch {
            throw .invalidExtensions
        }
    }
}
