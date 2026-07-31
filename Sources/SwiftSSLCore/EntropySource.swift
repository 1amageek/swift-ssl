public protocol EntropySource: Sendable {
    func fill(_ destination: inout MutableSpan<UInt8>) throws(EntropyError)
}
