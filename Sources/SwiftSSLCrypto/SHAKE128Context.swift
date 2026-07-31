import SwiftSSLCore

public struct SHAKE128Context: ~Copyable, ExtendableOutputFunctionContext {
    private var core: KeccakCore

    public init() {
        core = KeccakCore(rateByteCount: 168, domainSeparator: 0x1F)
    }

    private init(core: KeccakCore) {
        self.core = core
    }

    public mutating func update(_ input: Span<UInt8>) throws(CryptoInputError) {
        try core.update(input)
    }

    public borrowing func clone() -> SHAKE128Context {
        SHAKE128Context(core: core)
    }

    public consuming func finalize(
        into output: inout MutableSpan<UInt8>
    ) throws(CryptoInputError) {
        core.finalize(into: &output)
    }
}
