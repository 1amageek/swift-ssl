import SwiftSSLCore

/// RFC 7748 X25519 key agreement using a fixed-radix field implementation.
public enum X25519: KeyAgreement {
    public typealias PublicKey = X25519PublicKey
    public typealias PrivateKey = X25519PrivateKey
    public typealias SharedSecret = X25519SharedSecret

    public static func sharedSecret(
        privateKey: borrowing X25519PrivateKey,
        peerPublicKey: borrowing X25519PublicKey
    ) throws(CryptoInputError) -> X25519SharedSecret {
        var output = privateKey.withBorrowedBytes { scalar in
            peerPublicKey.withBorrowedBytes { peer in
                X25519Montgomery.scalarMultiply(scalar: scalar, uCoordinate: peer)
            }
        }
        defer { X25519Montgomery.wipe(&output) }
        var nonZero: UInt8 = 0
        var index = 0
        while index < output.count {
            nonZero |= output[index]
            index += 1
        }
        guard nonZero != 0 else {
            throw .invalidPeerKey
        }
        do {
            return try X25519SharedSecret(consuming: output)
        } catch {
            throw .invalidPeerKey
        }
    }
}

public struct X25519PrivateKey: ~Copyable, Sendable {
    public static let byteCount = 32
    private let storage: SecretBytes

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.byteCount else {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
        do {
            storage = try SecretBytes(copying: bytes)
        } catch {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
    }

    public borrowing func withBorrowedBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes(body)
    }

    public borrowing func publicKey() -> X25519PublicKey {
        let bytes = withBorrowedBytes { scalar in
            X25519Montgomery.scalarMultiplyBase(scalar: scalar)
        }
        return X25519PublicKey(uncheckedBytes: bytes)
    }
}

public struct X25519PublicKey: Sendable, Equatable {
    public static let byteCount = 32
    private let storage: OwnedBytes

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.byteCount else {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
        storage = OwnedBytes(copying: bytes)
    }

    fileprivate init(uncheckedBytes bytes: ContiguousArray<UInt8>) {
        storage = OwnedBytes(consuming: bytes)
    }

    public var span: Span<UInt8> { storage.span }

    public borrowing func withBorrowedBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(storage.span)
    }
}

public struct X25519SharedSecret: ~Copyable, Sendable {
    public static let byteCount = 32
    private let storage: SecretBytes

    fileprivate init(consuming bytes: consuming ContiguousArray<UInt8>) throws(SecretMemoryError) {
        let byteCount = try SecretByteCount(bytes.count)
        storage = SecretBytes(byteCount: byteCount) { destination in
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }

    public borrowing func withBorrowedBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes(body)
    }
}

private enum X25519Montgomery {
    private static let basePointBytes: ContiguousArray<UInt8> =
        ContiguousArray([9] + [UInt8](repeating: 0, count: 31))

    // Unsafe boundary invariants:
    // - basePointBytes owns the 32-byte storage for the entire scoped borrow.
    // - The Span created from its buffer is consumed synchronously by scalarMultiply.
    // - No pointer or Span escapes the withUnsafeBufferPointer closure.
    // - The scalar and peer-coordinate spans are caller-owned immutable borrows.
    // - Field elements use initialized UInt8/Int64 storage and never bind or rebind memory.
    static func scalarMultiplyBase(scalar: Span<UInt8>) -> ContiguousArray<UInt8> {
        basePointBytes.withUnsafeBufferPointer { basePoint in
            scalarMultiply(
                scalar: scalar,
                uCoordinate: Span(_unsafeElements: basePoint)
            )
        }
    }

    static func scalarMultiply(scalar: Span<UInt8>, uCoordinate: Span<UInt8>) -> ContiguousArray<UInt8> {
        var scalarBytes = ContiguousArray<UInt8>(repeating: 0, count: 32)
        defer { wipe(&scalarBytes) }
        var index = 0
        while index < 32 { scalarBytes[index] = scalar[index]; index += 1 }
        scalarBytes[0] &= 248
        scalarBytes[31] &= 127
        scalarBytes[31] |= 64

        let x1 = Field25519(bytes: uCoordinate)
        var x2 = Field25519(one: true)
        var z2 = Field25519()
        var x3 = x1
        var z3 = Field25519(one: true)
        var swap: UInt64 = 0
        var bit = 254
        while bit >= 0 {
            let byte = bit >> 3
            let bitValue = UInt64((scalarBytes[byte] >> UInt8(bit & 7)) & 1)
            swap ^= bitValue
            Field25519.conditionalSwap(&x2, &x3, swap)
            Field25519.conditionalSwap(&z2, &z3, swap)
            swap = bitValue

            let a = x2 + z2
            let aa = a * a
            let b = x2 - z2
            let bb = b * b
            let e = aa - bb
            let c = x3 + z3
            let d = x3 - z3
            let da = d * a
            let cb = c * b
            x3 = (da + cb) * (da + cb)
            z3 = x1 * ((da - cb) * (da - cb))
            x2 = aa * bb
            z2 = e * (aa + Field25519(constant: 121665) * e)
            bit -= 1
        }
        Field25519.conditionalSwap(&x2, &x3, swap)
        Field25519.conditionalSwap(&z2, &z3, swap)
        return (x2 * z2.inverted()).bytes
    }

    static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(
                UnsafeMutableRawPointer(baseAddress),
                byteCount: buffer.count
            )
        }
    }
}

private struct Field25519 {
    private static let base: Int64 = 65_536
    private var limbs: [Int64]

    init() { limbs = [Int64](repeating: 0, count: 16) }
    init(one: Bool) { limbs = [Int64](repeating: 0, count: 16); limbs[0] = one ? 1 : 0 }
    init(constant: Int64) { limbs = [Int64](repeating: 0, count: 16); limbs[0] = constant; normalize() }

    init(bytes: Span<UInt8>) {
        limbs = [Int64](repeating: 0, count: 16)
        var index = 0
        while index < 16 {
            limbs[index] = Int64(bytes[index * 2]) | (Int64(bytes[index * 2 + 1]) << 8)
            index += 1
        }
        limbs[15] &= 0x7fff
        normalize()
    }

    var bytes: ContiguousArray<UInt8> {
        var value = self
        value.normalize()
        var result = ContiguousArray<UInt8>(repeating: 0, count: 32)
        var index = 0
        while index < 16 {
            result[index * 2] = UInt8(truncatingIfNeeded: value.limbs[index])
            result[index * 2 + 1] = UInt8(truncatingIfNeeded: value.limbs[index] >> 8)
            index += 1
        }
        result[31] &= 0x7f
        return result
    }

    static func +(lhs: Field25519, rhs: Field25519) -> Field25519 {
        var result = Field25519()
        var index = 0
        while index < 16 { result.limbs[index] = lhs.limbs[index] + rhs.limbs[index]; index += 1 }
        result.normalize()
        return result
    }

    static func -(lhs: Field25519, rhs: Field25519) -> Field25519 {
        var result = Field25519()
        var index = 0
        while index < 16 { result.limbs[index] = lhs.limbs[index] - rhs.limbs[index]; index += 1 }
        result.normalize()
        return result
    }

    static func *(lhs: Field25519, rhs: Field25519) -> Field25519 {
        var product = [Int64](repeating: 0, count: 32)
        var i = 0
        while i < 16 {
            var j = 0
            while j < 16 {
                product[i + j] += lhs.limbs[i] * rhs.limbs[j]
                j += 1
            }
            i += 1
        }
        i = 31
        while i >= 16 {
            product[i - 16] += product[i] * 38
            i -= 1
        }
        var result = Field25519()
        i = 0
        while i < 16 { result.limbs[i] = product[i]; i += 1 }
        result.normalize()
        return result
    }

    func inverted() -> Field25519 {
        var result = Field25519(one: true)
        let base = self
        var bit = 254
        while bit >= 0 {
            result = result * result
            // p - 2 = 2^255 - 21: bits 254...5 and bits 3, 1, and 0 are set.
            let set = bit >= 5 || bit == 3 || bit == 1 || bit == 0
            if set { result = result * base }
            bit -= 1
        }
        return result
    }

    static func conditionalSwap(_ lhs: inout Field25519, _ rhs: inout Field25519, _ swap: UInt64) {
        let mask = UInt64(truncatingIfNeeded: -Int64(swap))
        var index = 0
        while index < 16 {
            let difference = UInt64(bitPattern: lhs.limbs[index] ^ rhs.limbs[index]) & mask
            lhs.limbs[index] ^= Int64(bitPattern: difference)
            rhs.limbs[index] ^= Int64(bitPattern: difference)
            index += 1
        }
    }

    private mutating func normalize() {
        // Radix carries use arithmetic shifts so secret-dependent values do not
        // select a branch. Three fixed passes bound carries after multiplication
        // and the final subtraction is selected from its borrow mask.
        var repeatCount = 0
        while repeatCount < 3 {
            var carry: Int64 = 0
            var index = 0
            while index < 15 {
                let value = limbs[index] + carry
                carry = value >> 16
                limbs[index] = value - carry * Self.base
                index += 1
            }
            let value = limbs[15] + carry
            carry = value >> 16
            limbs[15] = value - carry * Self.base
            limbs[0] += carry * 38
            repeatCount += 1
        }
        let modulus: [Int64] = [65_517] + [Int64](repeating: 65_535, count: 14) + [32_767]
        var borrow: UInt64 = 0
        var differences = [Int64](repeating: 0, count: 16)
        var index = 0
        while index < 16 {
            let difference = limbs[index] - modulus[index] - Int64(borrow)
            borrow = UInt64(bitPattern: difference) >> 63
            differences[index] = difference + Int64(borrow * UInt64(Self.base))
            index += 1
        }
        let selectSubtraction = UInt64(0) &- (UInt64(1) &- borrow)
        index = 0
        while index < 16 {
            let selected = UInt64(bitPattern: differences[index]) & selectSubtraction
            let original = UInt64(bitPattern: limbs[index]) & ~selectSubtraction
            limbs[index] = Int64(bitPattern: selected | original)
            index += 1
        }
    }
}
