import SSLCore

public struct CertificateBytes: Sendable, Hashable {
    private let der: OwnedBytes

    public init(adopting der: consuming OwnedBytes) {
        self.der = der
    }

    public init(copying der: Span<UInt8>) {
        self.der = OwnedBytes(copying: der)
    }

    public var count: Int {
        der.count
    }

    public var span: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get {
            der.span
        }
    }
}
