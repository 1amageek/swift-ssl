import SwiftSSLCore

/// A validated RSA public key for verification-only operations.
public struct RSAPublicKey: Sendable, Hashable {
    public static let minimumModulusByteCount = 256
    public static let maximumModulusByteCount = 512

    private let modulus: OwnedBytes
    public let exponent: UInt64

    public init(
        modulus: Span<UInt8>,
        exponent: UInt64
    ) throws(CryptoInputError) {
        guard modulus.count >= Self.minimumModulusByteCount,
              modulus.count <= Self.maximumModulusByteCount else {
            throw .invalidLength(expected: Self.minimumModulusByteCount, actual: modulus.count)
        }
        guard modulus[0] != 0,
              exponent >= 3,
              exponent & 1 == 1,
              exponent <= UInt64(Int.max) else {
            throw .nonCanonicalEncoding
        }
        self.modulus = OwnedBytes(copying: modulus)
        self.exponent = exponent
    }

    public var modulusByteCount: Int { modulus.count }

    public borrowing func withModulusBytes<Result, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try body(modulus.span)
    }
}

public enum RSAPSSHash: Sendable, Hashable {
    case sha256
    case sha384
    case sha512

    public var digestByteCount: Int {
        switch self {
        case .sha256: return SHA256.digestByteCount
        case .sha384: return SHA384.digestByteCount
        case .sha512: return SHA512.digestByteCount
        }
    }
}

/// EMSA-PSS verification for RSA public keys.
///
/// This is deliberately a verification-only surface. The public exponent is
/// not secret, while the encoded message and all intermediate buffers remain
/// bounded by the caller-owned modulus size.
// FIXME(INCOMPLETE_IMPLEMENTATION): The RSA-PSS path is vector-tested and
// bounded, but its generic modular arithmetic still requires constant-time,
// differential, sanitizer, and performance release gates before it can be
// treated as a production authentication backend.
public enum RSAPSS {
    public static func verify(
        signature: Span<UInt8>,
        messageHash: Span<UInt8>,
        publicKey: borrowing RSAPublicKey,
        hash: RSAPSSHash,
        saltLength: Int? = nil
    ) throws(CryptoInputError) -> Bool {
        let modulusBytes = publicKey.modulusByteCount
        guard signature.count == modulusBytes else {
            throw .invalidLength(expected: modulusBytes, actual: signature.count)
        }
        guard messageHash.count == hash.digestByteCount else {
            throw .invalidLength(expected: hash.digestByteCount, actual: messageHash.count)
        }
        let selectedSaltLength = saltLength ?? hash.digestByteCount
        guard selectedSaltLength >= 0 else { throw .invalidLength(expected: 0, actual: selectedSaltLength) }

        let modulus = publicKey.withModulusBytes { bytes in
            RSAUInt(bytes: bytes)
        }
        let encoded = RSAUInt(bytes: signature)
        guard encoded < modulus else { throw .nonCanonicalEncoding }
        let recovered = RSAUInt.modularPower(
            encoded,
            exponent: publicKey.exponent,
            modulus: modulus
        )
        let encodedBytes = recovered.encoded(byteCount: modulusBytes)
        return try verifyEncodedMessage(
            encodedBytes: encodedBytes.span,
            messageHash: messageHash,
            hash: hash,
            saltLength: selectedSaltLength,
            modulus: modulus
        )
    }

    private static func verifyEncodedMessage(
        encodedBytes: Span<UInt8>,
        messageHash: Span<UInt8>,
        hash: RSAPSSHash,
        saltLength: Int,
        modulus: RSAUInt
    ) throws(CryptoInputError) -> Bool {
        let modulusBitCount = modulus.bitWidth
        let emBitCount = modulusBitCount - 1
        let emByteCount = (emBitCount + 7) / 8
        guard encodedBytes.count >= emByteCount else { return false }
        let leadingCount = encodedBytes.count - emByteCount
        let encodedMessage = encodedBytes.extracting(leadingCount..<encodedBytes.count)
        guard !encodedMessage.isEmpty else { return false }

        let digestByteCount = hash.digestByteCount
        guard emByteCount >= digestByteCount + saltLength + 2 else { return false }
        guard encodedMessage[encodedMessage.count - 1] == 0xBC else { return false }
        let unusedBits = 8 * emByteCount - emBitCount
        if unusedBits > 0 {
            let mask = UInt8(0xFF >> UInt8(unusedBits))
            guard encodedMessage[0] & ~mask == 0 else { return false }
        }

        let dbByteCount = emByteCount - digestByteCount - 1
        let maskedDB = encodedMessage.extracting(0..<dbByteCount)
        let recoveredHash = encodedMessage.extracting(dbByteCount..<(dbByteCount + digestByteCount))
        let mask = try mgf1(
            seed: recoveredHash,
            count: dbByteCount,
            hash: hash
        )
        var db = ContiguousArray<UInt8>(repeating: 0, count: dbByteCount)
        var index = 0
        while index < dbByteCount {
            db[index] = maskedDB[index] ^ mask[index]
            index += 1
        }
        if unusedBits > 0 {
            db[0] &= UInt8(0xFF >> UInt8(unusedBits))
        }

        let paddingCount = dbByteCount - saltLength - 1
        guard paddingCount >= 0 else { return false }
        index = 0
        while index < paddingCount {
            guard db[index] == 0 else { return false }
            index += 1
        }
        guard db[paddingCount] == 1 else { return false }
        let salt = db.span.extracting((paddingCount + 1)..<dbByteCount)

        var validationInput = ContiguousArray<UInt8>(repeating: 0, count: 8 + digestByteCount + saltLength)
        var messageIndex = 0
        while messageIndex < digestByteCount {
            validationInput[8 + messageIndex] = messageHash[messageIndex]
            messageIndex += 1
        }
        var saltIndex = 0
        while saltIndex < saltLength {
            validationInput[8 + digestByteCount + saltIndex] = salt[saltIndex]
            saltIndex += 1
        }
        let expectedHash = try hashDigest(validationInput.span, hash: hash)
        return ConstantTime.equal(recoveredHash, expectedHash.span)
    }

    private static func mgf1(
        seed: Span<UInt8>,
        count: Int,
        hash: RSAPSSHash
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        guard count >= 0, count <= 16 * 1024 * 1024 else {
            throw .invalidLength(expected: 0, actual: count)
        }
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(count)
        var counter: UInt32 = 0
        while result.count < count {
            var input = ContiguousArray<UInt8>(repeating: 0, count: seed.count + 4)
            var index = 0
            while index < seed.count {
                input[index] = seed[index]
                index += 1
            }
            input[seed.count] = UInt8(truncatingIfNeeded: counter >> 24)
            input[seed.count + 1] = UInt8(truncatingIfNeeded: counter >> 16)
            input[seed.count + 2] = UInt8(truncatingIfNeeded: counter >> 8)
            input[seed.count + 3] = UInt8(truncatingIfNeeded: counter)
            let digest = try hashDigest(input.span, hash: hash)
            let remaining = count - result.count
            let appendCount = min(remaining, digest.count)
            var appendIndex = 0
            while appendIndex < appendCount {
                result.append(digest[appendIndex])
                appendIndex += 1
            }
            guard counter != UInt32.max else { throw .invalidLength(expected: count, actual: result.count) }
            counter += 1
        }
        return result
    }

    private static func hashDigest(
        _ input: Span<UInt8>,
        hash: RSAPSSHash
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        var output = ContiguousArray<UInt8>(repeating: 0, count: hash.digestByteCount)
        var span = output.mutableSpan
        switch hash {
        case .sha256:
            try SHA256.hash(input, into: &span)
        case .sha384:
            try SHA384.hash(input, into: &span)
        case .sha512:
            try SHA512.hash(input, into: &span)
        }
        return output
    }
}

private struct RSAUInt: Equatable, Comparable {
    let words: ContiguousArray<UInt32>

    init(bytes: Span<UInt8>) {
        var result = ContiguousArray<UInt32>(repeating: 0, count: max(1, (bytes.count + 3) / 4))
        var index = 0
        while index < bytes.count {
            let source = bytes.count - 1 - index
            result[index / 4] |= UInt32(bytes[source]) << UInt32((index & 3) * 8)
            index += 1
        }
        self.words = result
    }

    init(words: ContiguousArray<UInt32>) { self.words = words }

    static func one(count: Int) -> RSAUInt {
        var words = ContiguousArray<UInt32>(repeating: 0, count: count)
        words[0] = 1
        return RSAUInt(words: words)
    }

    var bitWidth: Int {
        var index = words.count - 1
        while index > 0, words[index] == 0 { index -= 1 }
        let word = words[index]
        if word == 0 { return 0 }
        return index * 32 + (32 - word.leadingZeroBitCount)
    }

    var isZero: Bool { words.allSatisfy { $0 == 0 } }

    func encoded(byteCount: Int) -> ContiguousArray<UInt8> {
        var result = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
        var index = 0
        while index < byteCount {
            let word = index / 4
            if word < words.count {
                result[byteCount - 1 - index] = UInt8(truncatingIfNeeded: words[word] >> UInt32((index & 3) * 8))
            }
            index += 1
        }
        return result
    }

    static func modularPower(
        _ base: RSAUInt,
        exponent: UInt64,
        modulus: RSAUInt
    ) -> RSAUInt {
        var result = RSAUInt.one(count: modulus.words.count)
        var value = base.modulo(modulus)
        var exponent = exponent
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result.modularMultiply(value, modulus: modulus)
            }
            exponent >>= 1
            if exponent != 0 {
                value = value.modularMultiply(value, modulus: modulus)
            }
        }
        return result
    }

    func modulo(_ modulus: RSAUInt) -> RSAUInt {
        var value = self
        while value >= modulus { value = value - modulus }
        return value
    }

    func modularMultiply(_ other: RSAUInt, modulus: RSAUInt) -> RSAUInt {
        let count = modulus.words.count
        var product = ContiguousArray<UInt64>(repeating: 0, count: count * 2)
        var i = 0
        while i < count {
            var carry: UInt64 = 0
            var j = 0
            while j < count {
                let lhs = i < words.count ? words[i] : 0
                let rhs = j < other.words.count ? other.words[j] : 0
                let value = UInt64(lhs) * UInt64(rhs) + product[i + j] + carry
                product[i + j] = value & 0xFFFF_FFFF
                carry = value >> 32
                j += 1
            }
            var index = i + count
            while carry != 0, index < product.count {
                let value = product[index] + carry
                product[index] = value & 0xFFFF_FFFF
                carry = value >> 32
                index += 1
            }
            i += 1
        }

        var remainder = ContiguousArray<UInt64>(repeating: 0, count: count + 1)
        var bit = product.count * 32 - 1
        while bit >= 0 {
            var carry = (product[bit >> 5] >> UInt64(bit & 31)) & 1
            var index = 0
            while index < remainder.count {
                let value = (remainder[index] << 1) | carry
                remainder[index] = value & 0xFFFF_FFFF
                carry = value >> 32
                index += 1
            }
            let low = RSAUInt(truncating: remainder, count: count)
            if remainder[count] != 0 || low >= modulus {
                var borrow: UInt64 = 0
                index = 0
                while index < count {
                    let minuend = remainder[index]
                    let subtrahend = UInt64(modulus.words[index]) + borrow
                    if minuend < subtrahend {
                        remainder[index] = (UInt64(1) << 32) + minuend - subtrahend
                        borrow = 1
                    } else {
                        remainder[index] = minuend - subtrahend
                        borrow = 0
                    }
                    index += 1
                }
                remainder[count] -= borrow
            }
            bit -= 1
        }
        return RSAUInt(truncating: remainder, count: count)
    }

    static func - (lhs: RSAUInt, rhs: RSAUInt) -> RSAUInt {
        var result = ContiguousArray<UInt32>(repeating: 0, count: lhs.words.count)
        var borrow: UInt64 = 0
        var index = 0
        while index < result.count {
            let minuend = UInt64(lhs.words[index])
            let subtrahend = UInt64(rhs.words[index]) + borrow
            if minuend < subtrahend {
                result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - subtrahend)
                borrow = 1
            } else {
                result[index] = UInt32(truncatingIfNeeded: minuend - subtrahend)
                borrow = 0
            }
            index += 1
        }
        return RSAUInt(words: result)
    }

    static func < (lhs: RSAUInt, rhs: RSAUInt) -> Bool {
        var index = max(lhs.words.count, rhs.words.count) - 1
        while index >= 0 {
            let left = index < lhs.words.count ? lhs.words[index] : 0
            let right = index < rhs.words.count ? rhs.words[index] : 0
            if left != right { return left < right }
            index -= 1
        }
        return false
    }

    private init(truncating words: ContiguousArray<UInt64>, count: Int) {
        var result = ContiguousArray<UInt32>(repeating: 0, count: count)
        var index = 0
        while index < count {
            result[index] = UInt32(truncatingIfNeeded: words[index])
            index += 1
        }
        self.words = result
    }
}
