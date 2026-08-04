import DTLSWireCore

/// One plaintext record in a retained handshake flight.
///
/// The record epoch is captured when the flight is first encoded. Retransmission
/// preserves the handshake bytes and epoch/key selection while allocating a new
/// record sequence number. `[UInt8]` is copy-on-write, so retaining the recipe
/// shares the handshake storage rather than materializing another payload copy.
struct DTLSFlightRecord: Sendable, Equatable {
    let contentType: DTLSContentType
    let plaintext: [UInt8]
    let epoch: UInt16
}

/// The ordered record recipe for one UDP datagram flight.
///
/// The current engine emits one datagram per flight. Keeping the datagram nesting
/// explicit prevents the retransmission layer from erasing packet boundaries when
/// handshake fragmentation is added.
struct DTLSFlightRecipe: Sendable, Equatable {
    let datagrams: [[DTLSFlightRecord]]

    var isEmpty: Bool {
        datagrams.allSatisfy { $0.isEmpty }
    }
}

/// Re-encodes every record in a retained flight without changing its datagram
/// boundaries. The record engine allocates a fresh sequence number for each
/// record's retained epoch.
func encodeDTLSFlight(
    _ recipe: DTLSFlightRecipe,
    using record: inout DTLSRecordEngine
) throws(DTLSEngineError) -> [[UInt8]] {
    var datagrams: [[UInt8]] = []
    datagrams.reserveCapacity(recipe.datagrams.count)
    for records in recipe.datagrams {
        var datagram: [UInt8] = []
        for flightRecord in records {
            let encoded = try record.encodeFlightRecord(flightRecord)
            datagram.append(contentsOf: encoded)
        }
        datagrams.append(datagram)
    }
    return datagrams
}
