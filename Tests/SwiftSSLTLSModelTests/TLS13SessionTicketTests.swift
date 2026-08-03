import SwiftSSLCore
import SwiftSSLTLS
import XCTest

final class TLS13SessionTicketTests: XCTestCase {
    func testNewSessionTicketRoundTrip() throws {
        let nonce = ContiguousArray<UInt8>([1, 2, 3])
        let ticket = ContiguousArray<UInt8>([0xA0, 0xB0, 0xC0])
        let extensions = ContiguousArray<UInt8>([0x12, 0x34, 0x00, 0x00])
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
        XCTAssertNil(parsed.maximumEarlyDataByteCount)
    }

    func testEarlyDataExtensionRoundTrip() throws {
        let message = try TLS13SessionTicketCodec.makeNewSessionTicket(
            lifetime: 3_600,
            ageAdd: 7,
            ticketNonce: ContiguousArray<UInt8>([1]).span,
            ticket: ContiguousArray<UInt8>([2]).span,
            maximumEarlyDataByteCount: 4_096
        )
        let parsed = try TLS13SessionTicketCodec.parseNewSessionTicket(
            message.span
        )
        XCTAssertEqual(parsed.maximumEarlyDataByteCount, 4_096)
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
            0x12, 0x34, 0x00, 0x00,
            0x12, 0x34, 0x00, 0x00,
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
            XCTAssertEqual(error, .duplicateExtension(0x1234))
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
