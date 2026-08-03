import SSLCore

public enum DTLS13ReplayDecision: Sendable, Equatable {
    case accepted
    case replayed
    case tooOld
}

public enum DTLS13ReplayError: Error, Sendable, Equatable {
    case invalidSequenceNumber(UInt64)
}

/// A bounded DTLS 1.3 anti-replay window for one epoch.
///
/// The window owns only a largest sequence number and a 64-bit bitmap. The
/// caller must instantiate a separate value for each epoch; epoch transitions
/// are not inferred from a packet and therefore cannot silently reuse state.
public struct DTLS13ReplayWindow: Sendable, Equatable {
    public static let maximumSequenceNumber: UInt64 = 0x0000_FFFF_FFFF_FFFF
    public static let windowBitCount = UInt64.bitWidth

    private var largest: UInt64?
    private var bitmap: UInt64

    public init() {
        largest = nil
        bitmap = 0
    }

    public var largestReceived: UInt64? { largest }

    public func contains(_ sequenceNumber: UInt64) throws(DTLS13ReplayError) -> Bool {
        guard sequenceNumber <= Self.maximumSequenceNumber else {
            throw .invalidSequenceNumber(sequenceNumber)
        }
        guard let largest else { return false }
        guard sequenceNumber <= largest else { return false }
        let distance = largest - sequenceNumber
        guard distance < Self.windowBitCount else { return false }
        return (bitmap & (UInt64(1) << distance)) != 0
    }

    /// Classifies and records one sequence number.
    public mutating func accept(
        _ sequenceNumber: UInt64
    ) throws(DTLS13ReplayError) -> DTLS13ReplayDecision {
        guard sequenceNumber <= Self.maximumSequenceNumber else {
            throw .invalidSequenceNumber(sequenceNumber)
        }
        guard let largest else {
            self.largest = sequenceNumber
            bitmap = 1
            return .accepted
        }

        if sequenceNumber > largest {
            let distance = sequenceNumber - largest
            bitmap = distance >= Self.windowBitCount
                ? 1
                : (bitmap << distance) | 1
            self.largest = sequenceNumber
            return .accepted
        }

        let distance = largest - sequenceNumber
        guard distance < Self.windowBitCount else { return .tooOld }
        let mask = UInt64(1) << distance
        guard bitmap & mask == 0 else { return .replayed }
        bitmap |= mask
        return .accepted
    }
}
