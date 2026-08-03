public enum PublicKeyAlgorithm: Sendable, Hashable {
    case x25519
    case ed25519
    case rsaEncryption
    case ecPublicKey(curve: NamedCurve)
    case unknown(objectIdentifier: ContiguousArray<UInt64>)
}

public enum NamedCurve: Sendable, Hashable {
    case prime256v1
    case secp384r1
    case secp521r1
    case unknown(objectIdentifier: ContiguousArray<UInt64>)
}
