import SwiftSSLCore

public struct PEMBlock: Sendable, Hashable {
    public let label: String
    private let der: OwnedBytes

    public init(label: String, der: consuming OwnedBytes) throws(PEMError) {
        guard Self.isValidLabel(label) else {
            throw .invalidLabel
        }
        guard !der.isEmpty else {
            throw .emptyDER
        }
        self.label = label
        self.der = der
    }

    public var derByteCount: Int {
        der.count
    }

    public borrowing func withDERBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(der.span)
    }

    internal static func isValidLabel(_ label: String) -> Bool {
        var count = 0
        var previousWasSpace = false
        for byte in label.utf8 {
            let isLetter = (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            let isDigit = byte >= 0x30 && byte <= 0x39
            let isSpace = byte == 0x20
            let isPunctuation = byte == 0x2D || byte == 0x5F
            guard isLetter || isDigit || isSpace || isPunctuation else {
                return false
            }
            if count == 0, isSpace {
                return false
            }
            previousWasSpace = isSpace
            count += 1
        }
        return count > 0 && !previousWasSpace
    }
}
