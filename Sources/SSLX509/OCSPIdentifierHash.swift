import SSLCore

/// SHA-1 restricted to RFC 6960 issuer and responder identifiers.
///
/// This internal construction is not an authentication primitive and is not
/// exposed as a selectable hash or signature algorithm. OCSP signatures are
/// verified separately with the modern X.509 signature policy.
enum OCSPIdentifierHash {
    static let digestByteCount = 20

    static func hash(_ input: Span<UInt8>) -> ContiguousArray<UInt8> {
        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xEFCDAB89
        var h2: UInt32 = 0x98BADCFE
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xC3D2E1F0
        var words = ContiguousArray<UInt32>(repeating: 0, count: 80)
        let length = UInt64(input.count) &* 8
        let blockCount = (input.count + 9 + 63) / 64

        var blockIndex = 0
        while blockIndex < blockCount {
            var wordIndex = 0
            while wordIndex < 16 {
                var word: UInt32 = 0
                var byteIndex = 0
                while byteIndex < 4 {
                    let absoluteIndex = blockIndex * 64 + wordIndex * 4
                        + byteIndex
                    let byte: UInt8
                    if absoluteIndex < input.count {
                        byte = input[absoluteIndex]
                    } else if absoluteIndex == input.count {
                        byte = 0x80
                    } else if absoluteIndex >= blockCount * 64 - 8 {
                        let shift = UInt64(
                            (blockCount * 64 - 1 - absoluteIndex) * 8
                        )
                        byte = UInt8(truncatingIfNeeded: length >> shift)
                    } else {
                        byte = 0
                    }
                    word = (word << 8) | UInt32(byte)
                    byteIndex += 1
                }
                words[wordIndex] = word
                wordIndex += 1
            }
            while wordIndex < 80 {
                words[wordIndex] = rotateLeft(
                    words[wordIndex - 3]
                        ^ words[wordIndex - 8]
                        ^ words[wordIndex - 14]
                        ^ words[wordIndex - 16],
                    by: 1
                )
                wordIndex += 1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            wordIndex = 0
            while wordIndex < 80 {
                let function: UInt32
                let constant: UInt32
                switch wordIndex {
                case 0..<20:
                    function = (b & c) | ((~b) & d)
                    constant = 0x5A827999
                case 20..<40:
                    function = b ^ c ^ d
                    constant = 0x6ED9EBA1
                case 40..<60:
                    function = (b & c) | (b & d) | (c & d)
                    constant = 0x8F1BBCDC
                default:
                    function = b ^ c ^ d
                    constant = 0xCA62C1D6
                }
                let temporary = rotateLeft(a, by: 5)
                    &+ function
                    &+ e
                    &+ constant
                    &+ words[wordIndex]
                e = d
                d = c
                c = rotateLeft(b, by: 30)
                b = a
                a = temporary
                wordIndex += 1
            }
            h0 &+= a
            h1 &+= b
            h2 &+= c
            h3 &+= d
            h4 &+= e
            blockIndex += 1
        }

        var output = ContiguousArray<UInt8>()
        output.reserveCapacity(digestByteCount)
        append(h0, to: &output)
        append(h1, to: &output)
        append(h2, to: &output)
        append(h3, to: &output)
        append(h4, to: &output)
        return output
    }

    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    private static func append(
        _ value: UInt32,
        to output: inout ContiguousArray<UInt8>
    ) {
        output.append(UInt8(truncatingIfNeeded: value >> 24))
        output.append(UInt8(truncatingIfNeeded: value >> 16))
        output.append(UInt8(truncatingIfNeeded: value >> 8))
        output.append(UInt8(truncatingIfNeeded: value))
    }
}
