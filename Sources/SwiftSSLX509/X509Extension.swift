import SwiftSSLCore

public struct X509Extension: Sendable, Hashable {
    public let objectIdentifier: ContiguousArray<UInt64>
    public let isCritical: Bool
    public let value: OwnedBytes

    internal init(
        objectIdentifier: ContiguousArray<UInt64>,
        isCritical: Bool,
        value: consuming OwnedBytes
    ) {
        self.objectIdentifier = objectIdentifier
        self.isCritical = isCritical
        self.value = value
    }
}
