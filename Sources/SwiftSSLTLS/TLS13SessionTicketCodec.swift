import SwiftSSLCore

public enum TLS13SessionTicketCodec {
    public static let newSessionTicketType: UInt8 = 4

    public static func makeNewSessionTicket(
        lifetime: UInt32,
        ageAdd: UInt32,
        ticketNonce: Span<UInt8>,
        ticket: Span<UInt8>,
        maximumEarlyDataByteCount: UInt32? = nil,
        extensions: Span<UInt8> = Span<UInt8>()
    ) throws(TLS13SessionTicketError) -> OwnedBytes {
        var encodedExtensions = ContiguousArray<UInt8>()
        encodedExtensions.reserveCapacity(
            extensions.count + (maximumEarlyDataByteCount == nil ? 0 : 8)
        )
        append(&encodedExtensions, extensions)
        if let maximumEarlyDataByteCount {
            appendUInt16(&encodedExtensions, TLS13NewSessionTicket.earlyDataExtensionType)
            appendUInt16(&encodedExtensions, 4)
            appendUInt32(&encodedExtensions, maximumEarlyDataByteCount)
        }
        let ticketValue = try TLS13NewSessionTicket(
            lifetime: lifetime,
            ageAdd: ageAdd,
            ticketNonce: ticketNonce,
            ticket: ticket,
            extensions: encodedExtensions.span
        )
        var body = ContiguousArray<UInt8>()
        body.reserveCapacity(
            4 + 4 + 1 + ticketNonce.count + 2 + ticket.count + 2
                + encodedExtensions.count
        )
        appendUInt32(&body, lifetime)
        appendUInt32(&body, ageAdd)
        body.append(UInt8(ticketNonce.count))
        append(&body, ticketNonce)
        appendUInt16(&body, UInt16(ticket.count))
        append(&body, ticket)
        appendUInt16(&body, UInt16(encodedExtensions.count))
        body.append(contentsOf: encodedExtensions)
        _ = ticketValue
        return finish(type: newSessionTicketType, body: body)
    }

    public static func parseNewSessionTicket(
        _ message: Span<UInt8>
    ) throws(TLS13SessionTicketError) -> TLS13NewSessionTicket {
        guard message.count >= 4, message[0] == newSessionTicketType else {
            throw .malformedMessage
        }
        let length = (Int(message[1]) << 16) | (Int(message[2]) << 8) | Int(message[3])
        guard length == message.count - 4 else { throw .malformedMessage }
        var cursor = ByteCursor(message.extracting(4..<message.count))
        do {
            let lifetime = try cursor.readUInt32BigEndian()
            let ageAdd = try cursor.readUInt32BigEndian()
            let nonceLength = Int(try cursor.readByte())
            let nonce = try cursor.readSpan(count: nonceLength)
            let ticketLength = Int(try cursor.readUInt16BigEndian())
            let ticket = try cursor.readSpan(count: ticketLength)
            let extensionLength = Int(try cursor.readUInt16BigEndian())
            let extensions = try cursor.readSpan(count: extensionLength)
            try cursor.requireFullyConsumed()
            return try TLS13NewSessionTicket(
                lifetime: lifetime,
                ageAdd: ageAdd,
                ticketNonce: nonce,
                ticket: ticket,
                extensions: extensions
            )
        } catch let error as TLS13SessionTicketError {
            throw error
        } catch {
            throw .malformedMessage
        }
    }

    private static func finish(type: UInt8, body: ContiguousArray<UInt8>) -> OwnedBytes {
        var output = ContiguousArray<UInt8>()
        output.reserveCapacity(body.count + 4)
        output.append(type)
        output.append(UInt8(truncatingIfNeeded: body.count >> 16))
        output.append(UInt8(truncatingIfNeeded: body.count >> 8))
        output.append(UInt8(truncatingIfNeeded: body.count))
        output.append(contentsOf: body)
        return OwnedBytes(consuming: output)
    }

    private static func appendUInt16(_ output: inout ContiguousArray<UInt8>, _ value: UInt16) {
        output.append(UInt8(truncatingIfNeeded: value >> 8))
        output.append(UInt8(truncatingIfNeeded: value))
    }

    private static func appendUInt32(_ output: inout ContiguousArray<UInt8>, _ value: UInt32) {
        output.append(UInt8(truncatingIfNeeded: value >> 24))
        output.append(UInt8(truncatingIfNeeded: value >> 16))
        output.append(UInt8(truncatingIfNeeded: value >> 8))
        output.append(UInt8(truncatingIfNeeded: value))
    }

    private static func append(_ output: inout ContiguousArray<UInt8>, _ input: Span<UInt8>) {
        var index = 0
        while index < input.count {
            output.append(input[index])
            index += 1
        }
    }
}
