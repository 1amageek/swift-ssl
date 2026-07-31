public enum ConstantTime {
    public static func equal(_ lhs: Span<UInt8>, _ rhs: Span<UInt8>) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }

        var difference: UInt8 = 0
        var index = 0
        while index < lhs.count {
            difference |= lhs[index] ^ rhs[index]
            index += 1
        }
        return difference == 0
    }
}
