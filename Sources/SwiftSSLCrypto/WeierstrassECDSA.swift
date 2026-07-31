import SwiftSSLCore

/// ECDSA signing and verification for the NIST P-384 and P-521 curves.
///
/// The implementation is intentionally private-width and owns no general
/// purpose big integer API. Arithmetic is performed over fixed-size 32-bit
/// limbs and all loops are bounded by the selected curve width. The public
/// entry points accept borrowed SEC1 keys and signatures; no pointer escapes
/// the scoped borrow.
// FIXME(INCOMPLETE_IMPLEMENTATION): P-384/P-521 signing and verification are
// vector- and certificate-tested, but the fixed-width arithmetic remains a
// validation backend until constant-time, differential, sanitizer, and
// performance release gates pass. TLS certificate authentication must not
// select these curves before those gates are recorded.
public enum P384ECDSA {
    public static let signatureByteCount = 96

    /// Creates an RFC 6979 deterministic raw signature encoded as `r || s`.
    /// The input is the digest selected by the caller's certificate profile.
    public static func sign(
        messageHash: Span<UInt8>,
        privateKey: borrowing P384PrivateKey
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        try privateKey.withBorrowedScalar { scalar throws(CryptoInputError) in
            try WeierstrassECDSA.sign(
                messageHash: messageHash,
                privateScalar: scalar,
                curve: .p384
            )
        }
    }

    public static func verify(
        signature: Span<UInt8>,
        messageHash: Span<UInt8>,
        publicKey: Span<UInt8>
    ) throws(CryptoInputError) -> Bool {
        try WeierstrassECDSA.verify(
            signature: signature,
            messageHash: messageHash,
            publicKey: publicKey,
            curve: .p384
        )
    }
}

public enum P521ECDSA {
    public static let signatureByteCount = 132

    /// Creates an RFC 6979 deterministic raw signature encoded as `r || s`.
    /// The input is the digest selected by the caller's certificate profile.
    public static func sign(
        messageHash: Span<UInt8>,
        privateKey: borrowing P521PrivateKey
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        try privateKey.withBorrowedScalar { scalar throws(CryptoInputError) in
            try WeierstrassECDSA.sign(
                messageHash: messageHash,
                privateScalar: scalar,
                curve: .p521
            )
        }
    }

    public static func verify(
        signature: Span<UInt8>,
        messageHash: Span<UInt8>,
        publicKey: Span<UInt8>
    ) throws(CryptoInputError) -> Bool {
        try WeierstrassECDSA.verify(
            signature: signature,
            messageHash: messageHash,
            publicKey: publicKey,
            curve: .p521
        )
    }
}

/// NIST P-384 ECDH key agreement.
// FIXME(INCOMPLETE_IMPLEMENTATION): The fixed-width P-384 ECDH backend is
// vector-tested and bounded, but constant-time and differential release gates
// are still required before protocol selection.
public enum P384: KeyAgreement {
    public typealias PublicKey = P384PublicKey
    public typealias PrivateKey = P384PrivateKey
    public typealias SharedSecret = P384SharedSecret

    public static func sharedSecret(
        privateKey: borrowing P384PrivateKey,
        peerPublicKey: borrowing P384PublicKey
    ) throws(CryptoInputError) -> P384SharedSecret {
        let secret = privateKey.withBorrowedScalar { scalar in
            peerPublicKey.withBorrowedPoint { point in
                WeierstrassECDSA.Point.scalarMultiply(
                    point,
                    scalar: scalar,
                    curve: .p384
                )
            }
        }
        guard let affine = secret.affine(curve: .p384) else {
            throw .invalidPeerKey
        }
        do {
            return try P384SharedSecret(consuming: affine.x.encoded(byteCount: 48))
        } catch {
            throw .invalidPeerKey
        }
    }
}

/// NIST P-521 ECDH key agreement.
// FIXME(INCOMPLETE_IMPLEMENTATION): The fixed-width P-521 ECDH backend is
// vector-tested and bounded, but constant-time and differential release gates
// are still required before protocol selection.
public enum P521: KeyAgreement {
    public typealias PublicKey = P521PublicKey
    public typealias PrivateKey = P521PrivateKey
    public typealias SharedSecret = P521SharedSecret

    public static func sharedSecret(
        privateKey: borrowing P521PrivateKey,
        peerPublicKey: borrowing P521PublicKey
    ) throws(CryptoInputError) -> P521SharedSecret {
        let secret = privateKey.withBorrowedScalar { scalar in
            peerPublicKey.withBorrowedPoint { point in
                WeierstrassECDSA.Point.scalarMultiply(
                    point,
                    scalar: scalar,
                    curve: .p521
                )
            }
        }
        guard let affine = secret.affine(curve: .p521) else {
            throw .invalidPeerKey
        }
        do {
            return try P521SharedSecret(consuming: affine.x.encoded(byteCount: 66))
        } catch {
            throw .invalidPeerKey
        }
    }
}

public struct P384PrivateKey: ~Copyable, Sendable {
    public static let byteCount = 48
    private let storage: SecretBytes

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.byteCount else {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
        let scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
        guard !scalar.isZero, scalar < WeierstrassECDSA.Curve.p384.order else {
            throw .nonCanonicalEncoding
        }
        do {
            storage = try SecretBytes(copying: bytes)
        } catch {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
    }

    public static func generate(
        using entropy: borrowing any EntropySource
    ) throws(P384KeyGenerationError) -> P384PrivateKey {
        var attempt = 0
        while attempt < 256 {
            var bytes = ContiguousArray<UInt8>(repeating: 0, count: Self.byteCount)
            defer { Self.wipe(&bytes) }
            do {
                var destination = bytes.mutableSpan
                try entropy.fill(&destination)
            } catch let error {
                throw .entropy(error)
            }
            do {
                return try Self(bytes: bytes.span)
            } catch let error {
                switch error {
                case .nonCanonicalEncoding: attempt += 1
                default: throw .invalidScalar
                }
            }
        }
        throw .invalidScalar
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        // The temporary entropy buffer owns initialized UInt8 storage for
        // this scope; the raw pointer is borrowed only by SecureWipe and
        // never escapes the closure before the array releases its allocation.
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }

    public static func generate() throws(P384KeyGenerationError) -> P384PrivateKey {
        try Self.generate(using: SystemEntropySource())
    }

    public borrowing func publicKey() -> P384PublicKey {
        let point = storage.withBorrowedBytes { bytes in
            let scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
            return WeierstrassECDSA.Point.scalarMultiply(
                .generator(.p384),
                scalar: scalar,
                curve: .p384
            )
        }
        return P384PublicKey(uncheckedPoint: point)
    }

    fileprivate borrowing func withBorrowedScalar<Result: ~Copyable, Failure: Error>(
        _ body: (WeierstrassECDSA.FixedUInt) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes { (bytes: Span<UInt8>) throws(Failure) -> Result in
            try body(WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount))
        }
    }
}

public struct P384PublicKey: Sendable, Equatable {
    public static let uncompressedByteCount = 97
    private let storage: OwnedBytes
    fileprivate let point: WeierstrassECDSA.Point

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.uncompressedByteCount else {
            throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
        }
        guard let point = WeierstrassECDSA.Point.decode(bytes, curve: .p384) else {
            throw .invalidPeerKey
        }
        storage = OwnedBytes(copying: bytes)
        self.point = point
    }

    fileprivate init(uncheckedPoint point: WeierstrassECDSA.Point) {
        let encoded = point.encoded(curve: .p384) ?? []
        storage = OwnedBytes(consuming: encoded)
        self.point = point
    }

    public var span: Span<UInt8> { storage.span }

    fileprivate borrowing func withBorrowedPoint<Result: ~Copyable>(
        _ body: (WeierstrassECDSA.Point) throws -> Result
    ) rethrows -> Result {
        try body(point)
    }
}

public struct P384SharedSecret: ~Copyable, Sendable {
    public static let byteCount = 48
    private let storage: SecretBytes

    fileprivate init(consuming bytes: consuming ContiguousArray<UInt8>) throws(SecretMemoryError) {
        storage = SecretBytes(byteCount: try SecretByteCount(bytes.count)) { destination in
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes(body)
    }
}

public struct P521PrivateKey: ~Copyable, Sendable {
    public static let byteCount = 66
    private let storage: SecretBytes

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.byteCount else {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
        let scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
        guard !scalar.isZero, scalar < WeierstrassECDSA.Curve.p521.order else {
            throw .nonCanonicalEncoding
        }
        do {
            storage = try SecretBytes(copying: bytes)
        } catch {
            throw .invalidLength(expected: Self.byteCount, actual: bytes.count)
        }
    }

    public static func generate(
        using entropy: borrowing any EntropySource
    ) throws(P521KeyGenerationError) -> P521PrivateKey {
        var attempt = 0
        while attempt < 256 {
            var bytes = ContiguousArray<UInt8>(repeating: 0, count: Self.byteCount)
            defer { Self.wipe(&bytes) }
            do {
                var destination = bytes.mutableSpan
                try entropy.fill(&destination)
            } catch let error {
                throw .entropy(error)
            }
            // P-521 uses only one significant bit in the leading byte.
            bytes[0] &= 0x01
            do {
                return try Self(bytes: bytes.span)
            } catch let error {
                switch error {
                case .nonCanonicalEncoding: attempt += 1
                default: throw .invalidScalar
                }
            }
        }
        throw .invalidScalar
    }

    private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
        // The temporary entropy buffer owns initialized UInt8 storage for
        // this scope; the raw pointer is borrowed only by SecureWipe and
        // never escapes the closure before the array releases its allocation.
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            SecureWipe.erase(UnsafeMutableRawPointer(baseAddress), byteCount: buffer.count)
        }
    }

    public static func generate() throws(P521KeyGenerationError) -> P521PrivateKey {
        try Self.generate(using: SystemEntropySource())
    }

    public borrowing func publicKey() -> P521PublicKey {
        let point = storage.withBorrowedBytes { bytes in
            let scalar = WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount)
            return WeierstrassECDSA.Point.scalarMultiply(
                .generator(.p521),
                scalar: scalar,
                curve: .p521
            )
        }
        return P521PublicKey(uncheckedPoint: point)
    }

    fileprivate borrowing func withBorrowedScalar<Result: ~Copyable, Failure: Error>(
        _ body: (WeierstrassECDSA.FixedUInt) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes { (bytes: Span<UInt8>) throws(Failure) -> Result in
            try body(WeierstrassECDSA.FixedUInt(bytes: bytes, byteCount: Self.byteCount))
        }
    }
}

public struct P521PublicKey: Sendable, Equatable {
    public static let uncompressedByteCount = 133
    private let storage: OwnedBytes
    fileprivate let point: WeierstrassECDSA.Point

    public init(bytes: Span<UInt8>) throws(CryptoInputError) {
        guard bytes.count == Self.uncompressedByteCount else {
            throw .invalidLength(expected: Self.uncompressedByteCount, actual: bytes.count)
        }
        guard let point = WeierstrassECDSA.Point.decode(bytes, curve: .p521) else {
            throw .invalidPeerKey
        }
        storage = OwnedBytes(copying: bytes)
        self.point = point
    }

    fileprivate init(uncheckedPoint point: WeierstrassECDSA.Point) {
        let encoded = point.encoded(curve: .p521) ?? []
        storage = OwnedBytes(consuming: encoded)
        self.point = point
    }

    public var span: Span<UInt8> { storage.span }

    fileprivate borrowing func withBorrowedPoint<Result: ~Copyable>(
        _ body: (WeierstrassECDSA.Point) throws -> Result
    ) rethrows -> Result {
        try body(point)
    }
}

public struct P521SharedSecret: ~Copyable, Sendable {
    public static let byteCount = 66
    private let storage: SecretBytes

    fileprivate init(consuming bytes: consuming ContiguousArray<UInt8>) throws(SecretMemoryError) {
        storage = SecretBytes(byteCount: try SecretByteCount(bytes.count)) { destination in
            var index = 0
            while index < bytes.count {
                destination[index] = bytes[index]
                index += 1
            }
        }
    }

    public borrowing func withBorrowedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (Span<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result {
        try storage.withBorrowedBytes(body)
    }
}

public enum P384KeyGenerationError: Error, Sendable, Equatable {
    case entropy(EntropyError)
    case invalidScalar
}

public enum P521KeyGenerationError: Error, Sendable, Equatable {
    case entropy(EntropyError)
    case invalidScalar
}

enum WeierstrassECDSA {
    enum Curve {
        case p384
        case p521

        var byteCount: Int { self == .p384 ? 48 : 66 }
        var bitCount: Int { self == .p384 ? 384 : 521 }
        var signatureByteCount: Int { byteCount * 2 }

        var prime: FixedUInt {
            switch self {
            case .p384:
                return FixedUInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", byteCount: 48)
            case .p521:
                return FixedUInt(hex: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", byteCount: 66)
            }
        }

        var order: FixedUInt {
            switch self {
            case .p384:
                return FixedUInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", byteCount: 48)
            case .p521:
                return FixedUInt(hex: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", byteCount: 66)
            }
        }

        var curveB: FixedUInt {
            switch self {
            case .p384:
                return FixedUInt(hex: "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", byteCount: 48)
            case .p521:
                return FixedUInt(hex: "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", byteCount: 66)
            }
        }

        var generatorX: FixedUInt {
            switch self {
            case .p384:
                return FixedUInt(hex: "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", byteCount: 48)
            case .p521:
                return FixedUInt(hex: "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", byteCount: 66)
            }
        }

        var generatorY: FixedUInt {
            switch self {
            case .p384:
                return FixedUInt(hex: "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", byteCount: 48)
            case .p521:
                return FixedUInt(hex: "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", byteCount: 66)
            }
        }
    }

    fileprivate static func sign(
        messageHash: Span<UInt8>,
        privateScalar: FixedUInt,
        curve: Curve
    ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
        guard !messageHash.isEmpty else {
            throw .invalidLength(expected: 1, actual: 0)
        }
        let digest = FixedUInt(truncatingDigest: messageHash, curve: curve)
            .modulo(curve.order)
        var generator = try RFC6979State(
            privateScalar: privateScalar,
            messageScalar: digest,
            curve: curve
        )
        defer { generator.wipe() }

        var attempt = 0
        while attempt < 128 {
            let nonce = try generator.next()
            let noncePoint = Point.scalarMultiply(
                Point.generator(curve),
                scalar: nonce,
                curve: curve
            )
            guard let affine = noncePoint.affine(curve: curve) else {
                try generator.reject()
                attempt += 1
                continue
            }
            let r = affine.x.modulo(curve.order)
            guard !r.isZero else {
                try generator.reject()
                attempt += 1
                continue
            }
            let inverse = nonce.power(
                curve.order.subtractingSmall(2),
                modulus: curve.order,
                bitCount: curve.bitCount
            )
            let s = inverse.moduloMultiply(
                digest.moduloAdd(
                    r.moduloMultiply(privateScalar, modulus: curve.order),
                    modulus: curve.order
                ),
                modulus: curve.order
            )
            guard !s.isZero else {
                try generator.reject()
                attempt += 1
                continue
            }
            var result = ContiguousArray<UInt8>()
            result.reserveCapacity(curve.signatureByteCount)
            result.append(contentsOf: r.encoded(byteCount: curve.byteCount))
            result.append(contentsOf: s.encoded(byteCount: curve.byteCount))
            return result
        }
        throw .invalidSignature
    }

    private struct RFC6979State {
        private enum HashKind {
            case sha384
            case sha512

            var byteCount: Int {
                switch self {
                case .sha384: return SHA384.digestByteCount
                case .sha512: return SHA512.digestByteCount
                }
            }
        }

        private var key: ContiguousArray<UInt8>
        private var value: ContiguousArray<UInt8>
        private let hash: HashKind
        private let curve: Curve

        init(
            privateScalar: FixedUInt,
            messageScalar: FixedUInt,
            curve: Curve
        ) throws(CryptoInputError) {
            hash = curve == .p384 ? .sha384 : .sha512
            self.curve = curve
            key = ContiguousArray(repeating: 0, count: hash.byteCount)
            value = ContiguousArray(repeating: 1, count: hash.byteCount)
            var input = ContiguousArray<UInt8>()
            input.reserveCapacity(value.count + 1 + curve.byteCount * 2)
            input.append(contentsOf: value)
            input.append(0)
            input.append(contentsOf: privateScalar.encoded(byteCount: curve.byteCount))
            input.append(contentsOf: messageScalar.encoded(byteCount: curve.byteCount))
            defer { Self.wipe(&input) }
            key = try Self.hmac(input.span, key: key.span, hash: hash)
            value = try Self.hmac(value.span, key: key.span, hash: hash)
            input.removeAll(keepingCapacity: true)
            input.append(contentsOf: value)
            input.append(1)
            input.append(contentsOf: privateScalar.encoded(byteCount: curve.byteCount))
            input.append(contentsOf: messageScalar.encoded(byteCount: curve.byteCount))
            key = try Self.hmac(input.span, key: key.span, hash: hash)
            value = try Self.hmac(value.span, key: key.span, hash: hash)
        }

        mutating func next() throws(CryptoInputError) -> FixedUInt {
            var attempt = 0
            while attempt < 128 {
                value = try Self.hmac(value.span, key: key.span, hash: hash)
                let candidate = FixedUInt(bytes: value.span, byteCount: curve.byteCount)
                if !candidate.isZero, candidate < curve.order {
                    return candidate
                }
                try reject()
                attempt += 1
            }
            throw .invalidSignature
        }

        mutating func reject() throws(CryptoInputError) {
            var input = ContiguousArray<UInt8>()
            input.reserveCapacity(value.count + 1)
            input.append(contentsOf: value)
            input.append(0)
            defer { Self.wipe(&input) }
            key = try Self.hmac(input.span, key: key.span, hash: hash)
            value = try Self.hmac(value.span, key: key.span, hash: hash)
        }

        mutating func wipe() {
            Self.wipe(&key)
            Self.wipe(&value)
        }

        private static func hmac(
            _ message: Span<UInt8>,
            key: Span<UInt8>,
            hash: HashKind
        ) throws(CryptoInputError) -> ContiguousArray<UInt8> {
            var output = ContiguousArray<UInt8>(repeating: 0, count: hash.byteCount)
            var destination = output.mutableSpan
            switch hash {
            case .sha384:
                var context = try HMACSHA384Context(authenticatingWith: key)
                try context.update(message)
                try context.finalize(into: &destination)
            case .sha512:
                var context = try HMACSHA512Context(authenticatingWith: key)
                try context.update(message)
                try context.finalize(into: &destination)
            }
            return output
        }

        private static func wipe(_ bytes: inout ContiguousArray<UInt8>) {
            bytes.withUnsafeMutableBufferPointer { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                SecureWipe.erase(
                    UnsafeMutableRawPointer(baseAddress),
                    byteCount: buffer.count
                )
            }
        }
    }

    fileprivate static func verify(
        signature: Span<UInt8>,
        messageHash: Span<UInt8>,
        publicKey: Span<UInt8>,
        curve: Curve
    ) throws(CryptoInputError) -> Bool {
        guard signature.count == curve.signatureByteCount else {
            throw .invalidLength(expected: curve.signatureByteCount, actual: signature.count)
        }
        guard !messageHash.isEmpty else {
            throw .invalidLength(expected: 1, actual: 0)
        }
        let r = FixedUInt(bytes: signature.extracting(0..<curve.byteCount), byteCount: curve.byteCount)
        let s = FixedUInt(bytes: signature.extracting(curve.byteCount..<curve.signatureByteCount), byteCount: curve.byteCount)
        guard !r.isZero, !s.isZero, r < curve.order, s < curve.order else {
            throw .nonCanonicalEncoding
        }
        guard let publicPoint = Point.decode(publicKey, curve: curve) else {
            throw .invalidPeerKey
        }

        let digest = FixedUInt(truncatingDigest: messageHash, curve: curve)
        let inverse = s.power(
            curve.order.subtractingSmall(2),
            modulus: curve.order,
            bitCount: curve.bitCount
        )
        let u1 = digest.moduloMultiply(inverse, modulus: curve.order)
        let u2 = r.moduloMultiply(inverse, modulus: curve.order)
        let first = Point.scalarMultiply(Point.generator(curve), scalar: u1, curve: curve)
        let second = Point.scalarMultiply(publicPoint, scalar: u2, curve: curve)
        guard let affine = first.adding(second, curve: curve).affine(curve: curve) else {
            return false
        }
        return affine.x.modulo(curve.order) == r
    }

    struct FixedUInt: Equatable, Comparable {
        let words: ContiguousArray<UInt32>

        init(byteCount: Int) {
            words = ContiguousArray(repeating: 0, count: (byteCount + 3) / 4)
        }

        init(bytes: Span<UInt8>, byteCount: Int) {
            var words = ContiguousArray<UInt32>(repeating: 0, count: (byteCount + 3) / 4)
            var index = 0
            while index < bytes.count {
                let destination = bytes.count - 1 - index
                let word = index / 4
                words[word] |= UInt32(bytes[destination]) << UInt32((index & 3) * 8)
                index += 1
            }
            self.words = words
        }

        init(truncatingDigest bytes: Span<UInt8>, curve: Curve) {
            let count = curve.byteCount
            if bytes.count >= count {
                self.init(bytes: bytes.extracting(0..<count), byteCount: count)
            } else {
                var padded = ContiguousArray<UInt8>(repeating: 0, count: count)
                let offset = count - bytes.count
                var index = 0
                while index < bytes.count {
                    padded[offset + index] = bytes[index]
                    index += 1
                }
                self.init(bytes: padded.span, byteCount: count)
            }
            if curve == .p521 {
                var mutable = ContiguousArray(words)
                mutable[mutable.count - 1] &= 0x0000_01FF
                self = FixedUInt(words: mutable)
            }
        }

        init(hex: String, byteCount: Int) {
            var bytes = ContiguousArray<UInt8>()
            var high: UInt8 = 0
            var haveHigh = false
            for character in hex.utf8 {
                let value: UInt8
                switch character {
                case 0x30...0x39: value = character - 0x30
                case 0x41...0x46: value = character - 0x41 + 10
                case 0x61...0x66: value = character - 0x61 + 10
                default: continue
                }
                if haveHigh {
                    bytes.append((high << 4) | value)
                    haveHigh = false
                } else {
                    high = value
                    haveHigh = true
                }
            }
            self.init(bytes: bytes.span, byteCount: byteCount)
        }

        init(words: ContiguousArray<UInt32>) { self.words = words }

        static func one(byteCount: Int) -> FixedUInt {
            var words = ContiguousArray<UInt32>(repeating: 0, count: (byteCount + 3) / 4)
            words[0] = 1
            return FixedUInt(words: words)
        }

        var isZero: Bool {
            var result: UInt32 = 0
            for word in words { result |= word }
            return result == 0
        }

        func encoded(byteCount: Int) -> ContiguousArray<UInt8> {
            var result = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
            var index = 0
            while index < byteCount {
                let word = index / 4
                let shift = UInt32((index & 3) * 8)
                result[byteCount - 1 - index] = UInt8(truncatingIfNeeded: words[word] >> shift)
                index += 1
            }
            return result
        }

        func modulo(_ modulus: FixedUInt) -> FixedUInt {
            var value = self
            while value >= modulus { value = value - modulus }
            return value
        }

        func moduloAdd(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
            let sum = self + other
            if sum < self {
                let complement = FixedUInt(byteCount: words.count * 4) - modulus
                return sum + complement
            }
            if sum >= modulus { return sum - modulus }
            return sum
        }

        func moduloSubtract(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
            if self >= other { return self - other }
            return modulus - (other - self)
        }

        func moduloMultiply(_ other: FixedUInt, modulus: FixedUInt) -> FixedUInt {
            var product = ContiguousArray<UInt64>(repeating: 0, count: words.count * 2)
            var i = 0
            while i < words.count {
                var carry: UInt64 = 0
                var j = 0
                while j < words.count {
                    let value = UInt64(words[i]) * UInt64(other.words[j]) + product[i + j] + carry
                    product[i + j] = value & 0xFFFF_FFFF
                    carry = value >> 32
                    j += 1
                }
                var index = i + words.count
                while carry != 0 && index < product.count {
                    let value = product[index] + carry
                    product[index] = value & 0xFFFF_FFFF
                    carry = value >> 32
                    index += 1
                }
                i += 1
            }

            var remainder = ContiguousArray<UInt64>(repeating: 0, count: words.count + 1)
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
                if remainder[words.count] != 0 || FixedUInt(truncating: remainder, count: words.count) >= modulus {
                    var borrow: UInt64 = 0
                    index = 0
                    while index < words.count {
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
                    remainder[words.count] -= borrow
                }
                bit -= 1
            }
            return FixedUInt(truncating: remainder, count: words.count)
        }

        func power(
            _ exponent: FixedUInt,
            modulus: FixedUInt,
            bitCount: Int
        ) -> FixedUInt {
            var result = FixedUInt.one(byteCount: words.count * 4)
            var bit = bitCount - 1
            while bit >= 0 {
                result = result.moduloMultiply(result, modulus: modulus)
                if ((exponent.words[bit >> 5] >> UInt32(bit & 31)) & 1) != 0 {
                    result = result.moduloMultiply(self, modulus: modulus)
                }
                bit -= 1
            }
            return result
        }

        static func - (lhs: FixedUInt, rhs: FixedUInt) -> FixedUInt {
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
            return FixedUInt(words: result)
        }

        static func + (lhs: FixedUInt, rhs: FixedUInt) -> FixedUInt {
            var result = ContiguousArray<UInt32>(repeating: 0, count: lhs.words.count)
            var carry: UInt64 = 0
            var index = 0
            while index < result.count {
                let sum = UInt64(lhs.words[index]) + UInt64(rhs.words[index]) + carry
                result[index] = UInt32(truncatingIfNeeded: sum)
                carry = sum >> 32
                index += 1
            }
            return FixedUInt(words: result)
        }

        static func < (lhs: FixedUInt, rhs: FixedUInt) -> Bool {
            var index = lhs.words.count - 1
            while index >= 0 {
                if lhs.words[index] != rhs.words[index] { return lhs.words[index] < rhs.words[index] }
                index -= 1
            }
            return false
        }

        fileprivate init(truncating words: ContiguousArray<UInt64>, count: Int) {
            var result = ContiguousArray<UInt32>(repeating: 0, count: count)
            var index = 0
            while index < count { result[index] = UInt32(truncatingIfNeeded: words[index]); index += 1 }
            self.words = result
        }
    }

    struct Point: Equatable {
        let x: FixedUInt
        let y: FixedUInt
        let z: FixedUInt

        static func generator(_ curve: Curve) -> Point {
            Point(x: curve.generatorX, y: curve.generatorY, z: FixedUInt.one(byteCount: curve.byteCount))
        }

        static func decode(_ bytes: Span<UInt8>, curve: Curve) -> Point? {
            guard bytes.count == 1 + curve.byteCount * 2, bytes[0] == 0x04 else { return nil }
            let x = FixedUInt(bytes: bytes.extracting(1..<(1 + curve.byteCount)), byteCount: curve.byteCount)
            let y = FixedUInt(bytes: bytes.extracting((1 + curve.byteCount)..<bytes.count), byteCount: curve.byteCount)
            guard x < curve.prime, y < curve.prime else { return nil }
            let point = Point(x: x, y: y, z: FixedUInt.one(byteCount: curve.byteCount))
            return point.isOnCurve(curve) ? point : nil
        }

        var isInfinity: Bool { z.isZero }

        func isOnCurve(_ curve: Curve) -> Bool {
            guard !isInfinity else { return false }
            let left = y.moduloMultiply(y, modulus: curve.prime)
            let x2 = x.moduloMultiply(x, modulus: curve.prime)
            let x3 = x2.moduloMultiply(x, modulus: curve.prime)
            let threeX = x.moduloAdd(x, modulus: curve.prime).moduloAdd(x, modulus: curve.prime)
            let right = x3.moduloSubtract(threeX, modulus: curve.prime)
                .moduloAdd(curve.curveB, modulus: curve.prime)
            return left == right
        }

        func affine(curve: Curve) -> Point? {
            guard !isInfinity else { return nil }
            let exponent = curve.prime.subtractingSmall(2)
            let inverse = z.power(
                exponent,
                modulus: curve.prime,
                bitCount: curve.bitCount
            )
            let inverseSquared = inverse.moduloMultiply(inverse, modulus: curve.prime)
            let affineX = x.moduloMultiply(inverseSquared, modulus: curve.prime)
            let affineY = y.moduloMultiply(inverseSquared, modulus: curve.prime).moduloMultiply(inverse, modulus: curve.prime)
            return Point(x: affineX, y: affineY, z: FixedUInt.one(byteCount: curve.byteCount))
        }

        func encoded(curve: Curve) -> ContiguousArray<UInt8>? {
            guard let affine = affine(curve: curve) else { return nil }
            var result = ContiguousArray<UInt8>(repeating: 0, count: 1 + curve.byteCount * 2)
            result[0] = 0x04
            let x = affine.x.encoded(byteCount: curve.byteCount)
            let y = affine.y.encoded(byteCount: curve.byteCount)
            var index = 0
            while index < curve.byteCount {
                result[1 + index] = x[index]
                result[1 + curve.byteCount + index] = y[index]
                index += 1
            }
            return result
        }

        func doubled(curve: Curve) -> Point {
            guard !isInfinity, !y.isZero else { return Point.infinity(curve) }
            let p = curve.prime
            let ySquared = y.moduloMultiply(y, modulus: p)
            let s = FixedUInt(byteCount: curve.byteCount).addingSmall(4).moduloMultiply(x, modulus: p).moduloMultiply(ySquared, modulus: p)
            let zSquared = z.moduloMultiply(z, modulus: p)
            let m = FixedUInt(byteCount: curve.byteCount).addingSmall(3)
                .moduloMultiply(x.moduloSubtract(zSquared, modulus: p), modulus: p)
                .moduloMultiply(x.moduloAdd(zSquared, modulus: p), modulus: p)
            let x3 = m.moduloMultiply(m, modulus: p)
                .moduloSubtract(s, modulus: p).moduloSubtract(s, modulus: p)
            let y4 = ySquared.moduloMultiply(ySquared, modulus: p)
            let y3 = m.moduloMultiply(s.moduloSubtract(x3, modulus: p), modulus: p)
                .moduloSubtract(y4.moduloMultiply(FixedUInt(byteCount: curve.byteCount).addingSmall(8), modulus: p), modulus: p)
            let z3 = FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(y, modulus: p).moduloMultiply(z, modulus: p)
            return Point(x: x3, y: y3, z: z3)
        }

        func adding(_ other: Point, curve: Curve) -> Point {
            guard !isInfinity else { return other }
            guard !other.isInfinity else { return self }
            let p = curve.prime
            let z1Squared = z.moduloMultiply(z, modulus: p)
            let z2Squared = other.z.moduloMultiply(other.z, modulus: p)
            let u1 = x.moduloMultiply(z2Squared, modulus: p)
            let u2 = other.x.moduloMultiply(z1Squared, modulus: p)
            let s1 = y.moduloMultiply(other.z, modulus: p).moduloMultiply(z2Squared, modulus: p)
            let s2 = other.y.moduloMultiply(z, modulus: p).moduloMultiply(z1Squared, modulus: p)
            if u1 == u2 { return s1 == s2 ? doubled(curve: curve) : Point.infinity(curve) }
            let h = u2.moduloSubtract(u1, modulus: p)
            let i = FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(h, modulus: p).moduloMultiply(FixedUInt(byteCount: curve.byteCount).addingSmall(2).moduloMultiply(h, modulus: p), modulus: p)
            let j = h.moduloMultiply(i, modulus: p)
            let r = FixedUInt(byteCount: curve.byteCount).addingSmall(2)
                .moduloMultiply(s2.moduloSubtract(s1, modulus: p), modulus: p)
            let v = u1.moduloMultiply(i, modulus: p)
            let x3 = r.moduloMultiply(r, modulus: p).moduloSubtract(j, modulus: p)
                .moduloSubtract(v, modulus: p).moduloSubtract(v, modulus: p)
            let y3 = r.moduloMultiply(v.moduloSubtract(x3, modulus: p), modulus: p)
                .moduloSubtract(
                    s1.moduloMultiply(j, modulus: p)
                        .moduloMultiply(FixedUInt(byteCount: curve.byteCount).addingSmall(2), modulus: p),
                    modulus: p
                )
            let zSum = z.moduloAdd(other.z, modulus: p)
            let z3 = zSum.moduloMultiply(zSum, modulus: p)
                .moduloSubtract(z1Squared, modulus: p)
                .moduloSubtract(z2Squared, modulus: p)
                .moduloMultiply(h, modulus: p)
            return Point(x: x3, y: y3, z: z3)
        }

        static func scalarMultiply(_ point: Point, scalar: FixedUInt, curve: Curve) -> Point {
            var result = Point.infinity(curve)
            var bit = curve.bitCount - 1
            while bit >= 0 {
                result = result.doubled(curve: curve)
                if ((scalar.words[bit >> 5] >> UInt32(bit & 31)) & 1) != 0 {
                    result = result.adding(point, curve: curve)
                }
                bit -= 1
            }
            return result
        }

        static func infinity(_ curve: Curve) -> Point {
            Point(x: FixedUInt(byteCount: curve.byteCount), y: FixedUInt(byteCount: curve.byteCount), z: FixedUInt(byteCount: curve.byteCount))
        }
    }
}

private extension WeierstrassECDSA.FixedUInt {
    func addingSmall(_ value: UInt32) -> Self {
        var result = words
        var carry = UInt64(value)
        var index = 0
        while carry != 0 && index < result.count {
            let sum = UInt64(result[index]) + carry
            result[index] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
            index += 1
        }
        return Self(words: result)
    }

    func subtractingSmall(_ value: UInt32) -> Self {
        var result = words
        var borrow = UInt64(value)
        var index = 0
        while borrow != 0 && index < result.count {
            let minuend = UInt64(result[index])
            if minuend < borrow {
                result[index] = UInt32(truncatingIfNeeded: (UInt64(1) << 32) + minuend - borrow)
                borrow = 1
            } else {
                result[index] = UInt32(truncatingIfNeeded: minuend - borrow)
                borrow = 0
            }
            index += 1
        }
        return Self(words: result)
    }
}
