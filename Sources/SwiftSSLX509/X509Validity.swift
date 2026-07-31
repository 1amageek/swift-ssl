import SwiftSSLCore

public struct X509Validity: Sendable, Hashable {
    public let notBefore: String
    public let notAfter: String

    internal init(
        notBefore: String,
        notAfter: String
    ) {
        self.notBefore = notBefore
        self.notAfter = notAfter
    }

    internal static func decode(
        notBefore: Span<UInt8>,
        notAfter: Span<UInt8>
    ) throws(X509CertificateError) -> X509Validity {
        guard let first = decodeTime(notBefore), let second = decodeTime(notAfter) else {
            throw .invalidValidity
        }
        return X509Validity(notBefore: first, notAfter: second)
    }

    private static func decodeTime(_ bytes: Span<UInt8>) -> String? {
        guard bytes.count == 13 || bytes.count == 15 else {
            return nil
        }
        guard bytes[bytes.count - 1] == 0x5A else {
            return nil
        }
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if index < bytes.count - 1 {
                guard byte >= 0x30 && byte <= 0x39 else {
                    return nil
                }
            }
            result.append(byte)
            index += 1
        }
        return String(decoding: result, as: UTF8.self)
    }
}
