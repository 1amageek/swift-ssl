@frozen public struct EncapsulationResult<
    Encapsulation: Sendable,
    SharedSecret: ~Copyable & Sendable
>: ~Copyable, Sendable {
    public let encapsulation: Encapsulation
    public let sharedSecret: SharedSecret

    public init(
        encapsulation: consuming Encapsulation,
        sharedSecret: consuming SharedSecret
    ) {
        self.encapsulation = encapsulation
        self.sharedSecret = sharedSecret
    }
}
