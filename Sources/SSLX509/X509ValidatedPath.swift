/// An immutable certificate path ordered from leaf to trust anchor.
public struct X509ValidatedPath: Sendable, Hashable {
    public let certificates: ContiguousArray<X509Certificate>

    internal init(
        certificates: consuming ContiguousArray<X509Certificate>
    ) {
        precondition(!certificates.isEmpty)
        self.certificates = certificates
    }

    public var leaf: X509Certificate {
        certificates[0]
    }

    public var trustAnchor: X509Certificate {
        certificates[certificates.count - 1]
    }
}
