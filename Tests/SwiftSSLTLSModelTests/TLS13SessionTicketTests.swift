import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class TLS13SessionTicketTests: XCTestCase {
    func testNewSessionTicketRoundTrip() throws {
        let nonce = ContiguousArray<UInt8>([1, 2, 3])
        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let extensions = ContiguousArray<UInt8>([0x00, 0x2A, 0x00, 0x00])
        let message = try TLS13SessionTicketCodec.makeNewSessionTicket(
            lifetime: 3_600,
            ageAdd: 0x1020_3040,
            ticketNonce: nonce.span,
            ticket: ticket.span,
            extensions: extensions.span
        )
        let parsed = try TLS13SessionTicketCodec.parseNewSessionTicket(message.span)
        XCTAssertEqual(parsed.lifetime, 3_600)
        XCTAssertEqual(parsed.ageAdd, 0x1020_3040)
        XCTAssertEqual(copy(parsed.ticketNonce.span), Array(nonce))
        XCTAssertEqual(copy(parsed.ticket.span), Array(ticket))
        XCTAssertEqual(copy(parsed.extensions.span), Array(extensions))
    }

    func testRejectsInvalidLifetimeAndDuplicateExtensions() throws {
        do {
            _ = try TLS13SessionTicketCodec.makeNewSessionTicket(
                lifetime: 0,
                ageAdd: 0,
                ticketNonce: Span<UInt8>(),
                ticket: ContiguousArray([1]).span
            )
            XCTFail("zero-lifetime ticket was accepted")
        } catch {
            XCTAssertEqual(error, .invalidLifetime(0))
        }

        let duplicateExtensions = ContiguousArray<UInt8>([
            0x00, 0x2A, 0x00, 0x00,
            0x00, 0x2A, 0x00, 0x00,
        ])
        do {
            _ = try TLS13SessionTicketCodec.makeNewSessionTicket(
                lifetime: 1,
                ageAdd: 0,
                ticketNonce: Span<UInt8>(),
                ticket: ContiguousArray([1]).span,
                extensions: duplicateExtensions.span
            )
            XCTFail("duplicate ticket extensions were accepted")
        } catch {
            XCTAssertEqual(error, .duplicateExtension(0x002A))
        }
    }

    private func copy(_ span: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(span.count)
        var index = 0
        while index < span.count {
            result.append(span[index])
            index += 1
        }
        return result
    }
}
