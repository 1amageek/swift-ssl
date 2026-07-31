public struct DERTag: Sendable, Hashable, Equatable {
    public let tagClass: DERTagClass
    public let isConstructed: Bool
    public let number: UInt

    public init(tagClass: DERTagClass, isConstructed: Bool, number: UInt) {
        self.tagClass = tagClass
        self.isConstructed = isConstructed
        self.number = number
    }
}
