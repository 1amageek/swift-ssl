import SwiftSSLASN1
import SwiftSSLCore
import SwiftSSLCrypto

/// Verifies a caller-borrowed signed payload using X.509 signature semantics.
///
/// This type owns no buffers or policy state. DER signature decoding and
/// digest construction are bounded within the call; input pointers cannot
/// escape their lexical borrows.
public enum X509SignedPayloadVerifier {
    public static func verify(
        signedBytes: Span<UInt8>,
        signature: Span<UInt8>,
        algorithm: borrowing X509SignatureAlgorithm,
        using verificationKey: borrowing SubjectPublicKeyInfo
    ) throws(X509SignatureVerificationError) {
        let identifier = algorithm.identifier
        if identifier.objectIdentifier == ed25519OID {
            guard identifier.parameters == .absent,
                  verificationKey.algorithm == .ed25519,
                  verificationKey.algorithmIdentifier.parameters == .absent
            else {
                throw .unsupportedAlgorithm
            }
            let valid: Bool
            do {
                valid = try verificationKey.withPublicKeyBytes { publicKey in
                    try Ed25519.verify(
                        signature: signature,
                        message: signedBytes,
                        using: try Ed25519PublicKey(bytes: publicKey)
                    )
                }
            } catch {
                throw .invalidSignature
            }
            guard valid else { throw .invalidSignature }
            return
        }

        if identifier.objectIdentifier == rsaPSSOID {
            try verifyRSAPSS(
                signedBytes: signedBytes,
                signature: signature,
                algorithm: algorithm,
                verificationKey: verificationKey
            )
            return
        }

        if let hash = rsaPKCS1v15Hash(for: identifier.objectIdentifier) {
            try verifyRSAPKCS1v15(
                signedBytes: signedBytes,
                signature: signature,
                identifier: identifier,
                verificationKey: verificationKey,
                hash: hash
            )
            return
        }

        let digest: ContiguousArray<UInt8>
        let componentByteCount: Int
        switch identifier.objectIdentifier {
        case ecdsaSHA256OID:
            componentByteCount = try requireSupportedECDSAKey(
                verificationKey,
                signatureParameters: identifier.parameters,
                curve: .prime256v1
            )
            digest = try hash(signedBytes, using: .sha256)
        case ecdsaSHA384OID:
            componentByteCount = try requireSupportedECDSAKey(
                verificationKey,
                signatureParameters: identifier.parameters,
                curve: .secp384r1
            )
            digest = try hash(signedBytes, using: .sha384)
        case ecdsaSHA512OID:
            componentByteCount = try requireSupportedECDSAKey(
                verificationKey,
                signatureParameters: identifier.parameters,
                curve: .secp521r1
            )
            digest = try hash(signedBytes, using: .sha512)
        default:
            throw .unsupportedAlgorithm
        }

        let rawSignature = try decodeECDSASignature(
            signature,
            componentByteCount: componentByteCount
        )
        let rawSignatureOwner = OwnedBytes(consuming: rawSignature)
        let digestOwner = OwnedBytes(consuming: digest)
        let valid: Bool
        do {
            valid = try verificationKey.withPublicKeyBytes { publicKey in
                switch verificationKey.algorithm {
                case .ecPublicKey(curve: .prime256v1):
                    return try P256ECDSA.verify(
                        signature: rawSignatureOwner.span,
                        messageHash: digestOwner.span,
                        using: try P256PublicKey(bytes: publicKey)
                    )
                case .ecPublicKey(curve: .secp384r1):
                    return try P384ECDSA.verify(
                        signature: rawSignatureOwner.span,
                        messageHash: digestOwner.span,
                        using: try P384PublicKey(bytes: publicKey)
                    )
                case .ecPublicKey(curve: .secp521r1):
                    return try P521ECDSA.verify(
                        signature: rawSignatureOwner.span,
                        messageHash: digestOwner.span,
                        using: try P521PublicKey(bytes: publicKey)
                    )
                default:
                    throw CryptoInputError.invalidPeerKey
                }
            }
        } catch {
            throw .invalidSignature
        }
        guard valid else { throw .invalidSignature }
    }

    private static func verifyRSAPSS(
        signedBytes: Span<UInt8>,
        signature: Span<UInt8>,
        algorithm: borrowing X509SignatureAlgorithm,
        verificationKey: borrowing SubjectPublicKeyInfo
    ) throws(X509SignatureVerificationError) {
        guard verificationKey.algorithm == .rsaEncryption,
              verificationKey.algorithmIdentifier.parameters == .null
                  || verificationKey.algorithmIdentifier.parameters == .absent,
              let hashAlgorithm = algorithm.rsaPSSHash,
              let saltLength = algorithm.rsaPSSSaltLength else {
            throw .unsupportedAlgorithm
        }
        let key = try parseRSAPublicKey(verificationKey)
        let digest: ContiguousArray<UInt8>
        switch hashAlgorithm {
        case .sha256: digest = try hash(signedBytes, using: .sha256)
        case .sha384: digest = try hash(signedBytes, using: .sha384)
        case .sha512: digest = try hash(signedBytes, using: .sha512)
        }
        let digestOwner = OwnedBytes(consuming: digest)
        let valid: Bool
        do {
            valid = try RSAPSS.verify(
                signature: signature,
                messageHash: digestOwner.span,
                publicKey: key,
                hash: hashAlgorithm,
                saltLength: saltLength
            )
        } catch {
            throw .invalidSignature
        }
        guard valid else { throw .invalidSignature }
    }

    private static func verifyRSAPKCS1v15(
        signedBytes: Span<UInt8>,
        signature: Span<UInt8>,
        identifier: DERAlgorithmIdentifier,
        verificationKey: borrowing SubjectPublicKeyInfo,
        hash hashAlgorithm: RSAPKCS1v15Hash
    ) throws(X509SignatureVerificationError) {
        guard identifier.parameters == .null
                  || identifier.parameters == .absent,
              verificationKey.algorithm == .rsaEncryption,
              verificationKey.algorithmIdentifier.parameters == .null
                  || verificationKey.algorithmIdentifier.parameters == .absent
        else {
            throw .unsupportedAlgorithm
        }
        let key = try parseRSAPublicKey(verificationKey)
        let digest: ContiguousArray<UInt8>
        switch hashAlgorithm {
        case .sha256: digest = try hash(signedBytes, using: .sha256)
        case .sha384: digest = try hash(signedBytes, using: .sha384)
        case .sha512: digest = try hash(signedBytes, using: .sha512)
        }
        let digestOwner = OwnedBytes(consuming: digest)
        let valid: Bool
        do {
            valid = try RSAPKCS1v15.verify(
                signature: signature,
                messageHash: digestOwner.span,
                publicKey: key,
                hash: hashAlgorithm
            )
        } catch {
            throw .invalidSignature
        }
        guard valid else { throw .invalidSignature }
    }

    private static func parseRSAPublicKey(
        _ verificationKey: borrowing SubjectPublicKeyInfo
    ) throws(X509SignatureVerificationError) -> RSAPublicKey {
        do {
            return try verificationKey.withPublicKeyBytes { encoded in
                var budget = try ParsingBudget(
                    limits: X509Certificate.defaultParsingLimits,
                    inputByteCount: encoded.count
                )
                var cursor = DERCursor(encoded)
                let root = try cursor.readElement(using: &budget)
                try cursor.requireFullyConsumed()
                guard root.tag == sequenceTag else {
                    throw X509SignatureVerificationError.invalidSignature
                }
                var body = DERCursor(root.contentBytes)
                let modulusElement = try body.readElement(using: &budget)
                let exponentElement = try body.readElement(using: &budget)
                try body.requireFullyConsumed()
                guard modulusElement.tag == integerTag,
                      exponentElement.tag == integerTag else {
                    throw X509SignatureVerificationError.invalidSignature
                }
                let encodedModulus = modulusElement.contentBytes
                guard !encodedModulus.isEmpty,
                      encodedModulus[0] & 0x80 == 0,
                      !(encodedModulus.count > 1
                        && encodedModulus[0] == 0
                        && encodedModulus[1] & 0x80 == 0) else {
                    throw X509SignatureVerificationError.invalidSignature
                }
                let modulus = encodedModulus[0] == 0
                    ? encodedModulus.extracting(1..<encodedModulus.count)
                    : encodedModulus
                let exponent = try DERPrimitiveCodec
                    .decodePositiveInteger(from: exponentElement)
                return try RSAPublicKey(
                    modulus: modulus,
                    exponent: exponent
                )
            }
        } catch {
            throw .invalidSignature
        }
    }

    private static func requireSupportedECDSAKey(
        _ key: borrowing SubjectPublicKeyInfo,
        signatureParameters: DERAlgorithmParameters,
        curve: NamedCurve
    ) throws(X509SignatureVerificationError) -> Int {
        let objectIdentifier: ContiguousArray<UInt64>
        let coordinateByteCount: Int
        switch curve {
        case .prime256v1:
            objectIdentifier = [1, 2, 840, 10045, 3, 1, 7]
            coordinateByteCount = 32
        case .secp384r1:
            objectIdentifier = [1, 3, 132, 0, 34]
            coordinateByteCount = 48
        case .secp521r1:
            objectIdentifier = [1, 3, 132, 0, 35]
            coordinateByteCount = 66
        case .unknown:
            throw .unsupportedAlgorithm
        }
        guard signatureParameters == .absent,
              key.algorithm == .ecPublicKey(curve: curve),
              key.algorithmIdentifier.parameters
                == .objectIdentifier(objectIdentifier) else {
            throw .unsupportedAlgorithm
        }
        return coordinateByteCount
    }

    private static func decodeECDSASignature(
        _ signature: Span<UInt8>,
        componentByteCount: Int
    ) throws(X509SignatureVerificationError) -> ContiguousArray<UInt8> {
        guard signature.count <= 256 else { throw .invalidSignature }
        var budget: ParsingBudget
        do {
            budget = try ParsingBudget(
                limits: X509Certificate.defaultParsingLimits,
                inputByteCount: signature.count
            )
        } catch {
            throw .invalidSignature
        }
        var cursor = DERCursor(signature)
        let root: DERElementView
        do {
            root = try cursor.readElement(using: &budget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .invalidSignature
        }
        guard root.tag == sequenceTag else { throw .invalidSignature }
        var body = DERCursor(root.contentBytes)
        let r: DERElementView
        let s: DERElementView
        do {
            r = try body.readElement(using: &budget)
            s = try body.readElement(using: &budget)
            try body.requireFullyConsumed()
        } catch {
            throw .invalidSignature
        }
        var raw = ContiguousArray<UInt8>(
            repeating: 0,
            count: componentByteCount * 2
        )
        try copyECDSAComponent(
            r,
            into: &raw,
            offset: 0,
            byteCount: componentByteCount
        )
        try copyECDSAComponent(
            s,
            into: &raw,
            offset: componentByteCount,
            byteCount: componentByteCount
        )
        return raw
    }

    private static func copyECDSAComponent(
        _ element: DERElementView,
        into output: inout ContiguousArray<UInt8>,
        offset: Int,
        byteCount: Int
    ) throws(X509SignatureVerificationError) {
        guard element.tag == integerTag,
              !element.contentBytes.isEmpty else {
            throw .invalidSignature
        }
        let encoded = element.contentBytes
        if encoded.count > 1, encoded[0] == 0 {
            guard encoded[1] & 0x80 != 0 else { throw .invalidSignature }
        } else {
            guard encoded[0] & 0x80 == 0 else { throw .invalidSignature }
        }
        let value = encoded[0] == 0
            ? encoded.extracting(1..<encoded.count)
            : encoded
        guard !value.isEmpty, value.count <= byteCount else {
            throw .invalidSignature
        }
        let destinationOffset = offset + byteCount - value.count
        var index = 0
        while index < value.count {
            output[destinationOffset + index] = value[index]
            index += 1
        }
    }

    private static func hash(
        _ input: Span<UInt8>,
        using algorithm: HashAlgorithm
    ) throws(X509SignatureVerificationError) -> ContiguousArray<UInt8> {
        var digest = ContiguousArray<UInt8>(
            repeating: 0,
            count: algorithm.digestByteCount
        )
        do {
            var output = digest.mutableSpan
            switch algorithm {
            case .sha256: try SHA256.hash(input, into: &output)
            case .sha384: try SHA384.hash(input, into: &output)
            case .sha512: try SHA512.hash(input, into: &output)
            }
        } catch {
            throw .invalidSignature
        }
        return digest
    }

    private static func rsaPKCS1v15Hash(
        for objectIdentifier: ContiguousArray<UInt64>
    ) -> RSAPKCS1v15Hash? {
        switch objectIdentifier {
        case rsaSHA256OID: return .sha256
        case rsaSHA384OID: return .sha384
        case rsaSHA512OID: return .sha512
        default: return nil
        }
    }

    private enum HashAlgorithm {
        case sha256
        case sha384
        case sha512

        var digestByteCount: Int {
            switch self {
            case .sha256: return SHA256.digestByteCount
            case .sha384: return SHA384.digestByteCount
            case .sha512: return SHA512.digestByteCount
            }
        }
    }

    private static let ed25519OID: ContiguousArray<UInt64> = [1, 3, 101, 112]
    private static let rsaPSSOID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 10,
    ]
    private static let rsaSHA256OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 11,
    ]
    private static let rsaSHA384OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 12,
    ]
    private static let rsaSHA512OID: ContiguousArray<UInt64> = [
        1, 2, 840, 113549, 1, 1, 13,
    ]
    private static let ecdsaSHA256OID: ContiguousArray<UInt64> = [
        1, 2, 840, 10045, 4, 3, 2,
    ]
    private static let ecdsaSHA384OID: ContiguousArray<UInt64> = [
        1, 2, 840, 10045, 4, 3, 3,
    ]
    private static let ecdsaSHA512OID: ContiguousArray<UInt64> = [
        1, 2, 840, 10045, 4, 3, 4,
    ]
    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let integerTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 2
    )
}
