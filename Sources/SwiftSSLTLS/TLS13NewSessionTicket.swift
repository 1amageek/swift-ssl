import SwiftSSLCore

public struct TLS13NewSessionTicket: Sendable, Hashable {
    public static let maximumLifetime: UInt32 = 604_800
    public static let maximumNonceByteCount = 255
    public static let maximumTicketByteCount = 65_535
    public static let earlyDataExtensionType: UInt16 = 0x002A

    public let lifetime: UInt32
    public let ageAdd: UInt32
    public let ticketNonce: OwnedBytes
    public let ticket: OwnedBytes
    /// Raw extension list contents, excluding the two-byte vector length.
    public let extensions: OwnedBytes
    public let maximumEarlyDataByteCount: UInt32?

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
        let maximumEarlyDataByteCount = try TLS13NewSessionTicket
            .validateExtensions(extensions)
        self.lifetime = lifetime
        self.ageAdd = ageAdd
        self.ticketNonce = OwnedBytes(copying: ticketNonce)
        self.ticket = OwnedBytes(copying: ticket)
        self.extensions = OwnedBytes(copying: extensions)
        self.maximumEarlyDataByteCount = maximumEarlyDataByteCount
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
    ) throws(TLS13SessionTicketError) -> UInt32? {
        var cursor = ByteCursor(bytes)
        var seen = Set<UInt16>()
        var maximumEarlyDataByteCount: UInt32?
        do {
            while !cursor.isAtEnd {
                let type = try cursor.readUInt16BigEndian()
                let length = Int(try cursor.readUInt16BigEndian())
                let value = try cursor.readSpan(count: length)
                guard seen.insert(type).inserted else {
                    throw TLS13SessionTicketError.duplicateExtension(type)
                }
                if type == earlyDataExtensionType {
                    guard value.count == 4 else {
                        throw TLS13SessionTicketError.invalidEarlyDataExtension
                    }
                    var valueCursor = ByteCursor(value)
                    maximumEarlyDataByteCount = try valueCursor.readUInt32BigEndian()
                }
            }
            return maximumEarlyDataByteCount
        } catch let error as TLS13SessionTicketError {
            throw error
        } catch {
            throw .invalidExtensions
        }
    }
}
