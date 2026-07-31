public enum TLS13SessionTicketError: Error, Sendable, Equatable {
    case malformedMessage
    case invalidLifetime(UInt32)
    case invalidNonceLength(Int)
    case invalidTicketLength(Int)
    case invalidExtensions
    case duplicateExtension(UInt16)
}
