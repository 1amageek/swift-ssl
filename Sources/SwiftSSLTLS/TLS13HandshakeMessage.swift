import SwiftSSLCore
import SwiftSSLASN1
import SwiftSSLCrypto
import SwiftSSLX509

public struct TLS13ClientHello: Sendable, Hashable {
    public let random: OwnedBytes
    public let keyShare: OwnedBytes
    public let cipherSuite: TLSCipherSuite
    public let preSharedKey: TLS13PreSharedKeyExtension?
}

public struct TLS13ServerHello: Sendable, Hashable {
    public let random: OwnedBytes
    public let keyShare: OwnedBytes
    public let cipherSuite: TLSCipherSuite
    public let selectedPreSharedKey: Bool
}

/// Signature schemes permitted by the modern TLS 1.3 profile.
public enum TLS13SignatureScheme: UInt16, Sendable, Hashable {
    case ecdsaP256SHA256 = 0x0403
    case ecdsaP384SHA384 = 0x0503
    case ecdsaP521SHA512 = 0x0603
    case rsaPSSRSAESHA256 = 0x0804
    case rsaPSSRSAESHA384 = 0x0805
    case rsaPSSRSAESHA512 = 0x0806
    case ed25519 = 0x0807
    case rsaPSSPSSSHA256 = 0x0809
    case rsaPSSPSSSHA384 = 0x080A
    case rsaPSSPSSSHA512 = 0x080B

    public var publicKeyByteCount: Int {
        switch self {
        case .ed25519: return 32
        case .ecdsaP256SHA256: return 65
        case .ecdsaP384SHA384: return 97
        case .ecdsaP521SHA512: return 133
        case .rsaPSSRSAESHA256, .rsaPSSRSAESHA384, .rsaPSSRSAESHA512,
             .rsaPSSPSSSHA256, .rsaPSSPSSSHA384, .rsaPSSPSSSHA512:
            return 0
        }
    }

    public var keyAlgorithm: PublicKeyAlgorithm {
        switch self {
        case .ed25519:
            return .ed25519
        case .ecdsaP256SHA256:
            return .ecPublicKey(curve: .prime256v1)
        case .ecdsaP384SHA384:
            return .ecPublicKey(curve: .secp384r1)
        case .ecdsaP521SHA512:
            return .ecPublicKey(curve: .secp521r1)
        case .rsaPSSRSAESHA256, .rsaPSSRSAESHA384, .rsaPSSRSAESHA512,
             .rsaPSSPSSSHA256, .rsaPSSPSSSHA384, .rsaPSSPSSSHA512:
            return .rsaEncryption
        }
    }
}

public struct TLS13CertificateVerify: Sendable, Hashable {
    public let signatureScheme: TLS13SignatureScheme
    public let signature: OwnedBytes

    public init(
        signatureScheme: TLS13SignatureScheme,
        signature: consuming OwnedBytes
    ) {
        self.signatureScheme = signatureScheme
        self.signature = signature
    }
}

public enum TLS13HandshakeCodec {
    public static let clientHelloType: UInt8 = 1
    public static let serverHelloType: UInt8 = 2
    public static let encryptedExtensionsType: UInt8 = 8
    public static let certificateType: UInt8 = 11
    public static let certificateVerifyType: UInt8 = 15
    public static let finishedType: UInt8 = 20
    public static let keyUpdateType: UInt8 = 24

    public static func makeClientHello(
        random: Span<UInt8>,
        keyShare: Span<UInt8>,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        preSharedKey: TLS13PreSharedKeyExtension? = nil
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        guard random.count == 32, keyShare.count == 32 else {
            throw .invalidKeyShare
        }
        guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else {
            throw .unsupportedCipherSuite(cipherSuite.rawValue)
        }
        var body = try Self.makeBuilder(maximumByteCount: 2 * 65_535, minimumCapacity: 128)
        do {
            try body.appendUInt16BigEndian(0x0303)
            try body.append(random)
            try body.append(0)
            try body.appendUInt16BigEndian(2)
            try body.appendUInt16BigEndian(cipherSuite.rawValue)
            try body.append(1)
            try body.append(0)
            var extensions = try Self.makeBuilder(maximumByteCount: 2 * 65_535, minimumCapacity: 48)
            try appendSupportedVersionsClient(to: &extensions)
            try appendKeyShare(to: &extensions, keyShare: keyShare)
            if let preSharedKey {
                let value: OwnedBytes
                do {
                    value = try preSharedKey.encodedValue()
                } catch {
                    throw TLS13HandshakeError.invalidPreSharedKey
                }
                try extensions.appendUInt16BigEndian(TLS13PreSharedKeyExtension.extensionType)
                try extensions.appendUInt16BigEndian(UInt16(value.count))
                try extensions.append(value.span)
            }
            guard extensions.count <= UInt16.max else {
                throw TLS13HandshakeError.invalidPreSharedKey
            }
            try body.appendUInt16BigEndian(UInt16(extensions.count))
            try body.append(extensions.finish().span)
            return finish(type: Self.clientHelloType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseClientHello(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> TLS13ClientHello {
        let body = try readBody(message, expectedType: Self.clientHelloType)
        var cursor = ByteCursor(body)
        do {
            guard try cursor.readUInt16BigEndian() == 0x0303 else { throw TLS13HandshakeError.malformedMessage }
            let random = OwnedBytes(copying: try cursor.readSpan(count: 32))
            guard try cursor.readByte() == 0 else { throw TLS13HandshakeError.malformedMessage }
            guard try cursor.readUInt16BigEndian() == 2,
                  let cipherSuite = TLSCipherSuite(rawValue: try cursor.readUInt16BigEndian()),
                  try cursor.readByte() == 1,
                  try cursor.readByte() == 0 else {
                throw TLS13HandshakeError.unsupportedCipherSuite(0)
            }
            let extensionsLength = Int(try cursor.readUInt16BigEndian())
            let extensions = try cursor.readSpan(count: extensionsLength)
            try cursor.requireFullyConsumed()
            let parsed = try parseClientExtensions(extensions)
            return TLS13ClientHello(
                random: random,
                keyShare: parsed.keyShare,
                cipherSuite: cipherSuite,
                preSharedKey: parsed.preSharedKey
            )
        } catch let error as TLS13HandshakeError {
            throw error
        } catch {
            throw .malformedMessage
        }
    }

    public static func makeServerHello(
        random: Span<UInt8>,
        keyShare: Span<UInt8>,
        cipherSuite: TLSCipherSuite = .aes128GCM_SHA256,
        selectedPreSharedKey: Bool = false
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        guard random.count == 32, keyShare.count == 32 else { throw .invalidKeyShare }
        guard TLSCipherSuite(rawValue: cipherSuite.rawValue) != nil else { throw .unsupportedCipherSuite(cipherSuite.rawValue) }
        var body = try Self.makeBuilder(maximumByteCount: 256, minimumCapacity: 100)
        do {
            try body.appendUInt16BigEndian(0x0303)
            try body.append(random)
            try body.append(0)
            try body.appendUInt16BigEndian(cipherSuite.rawValue)
            try body.append(0)
            var extensions = try Self.makeBuilder(maximumByteCount: 64, minimumCapacity: 40)
            try appendSupportedVersionsServer(to: &extensions)
            try appendKeyShare(to: &extensions, keyShare: keyShare)
            if selectedPreSharedKey {
                try extensions.appendUInt16BigEndian(TLS13PreSharedKeyExtension.extensionType)
                try extensions.appendUInt16BigEndian(2)
                try extensions.appendUInt16BigEndian(0)
            }
            try body.appendUInt16BigEndian(UInt16(extensions.count))
            try body.append(extensions.finish().span)
            return finish(type: Self.serverHelloType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseServerHello(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> TLS13ServerHello {
        let body = try readBody(message, expectedType: Self.serverHelloType)
        var cursor = ByteCursor(body)
        do {
            guard try cursor.readUInt16BigEndian() == 0x0303 else { throw TLS13HandshakeError.malformedMessage }
            let random = OwnedBytes(copying: try cursor.readSpan(count: 32))
            guard try cursor.readByte() == 0 else { throw TLS13HandshakeError.malformedMessage }
            guard let cipherSuite = TLSCipherSuite(rawValue: try cursor.readUInt16BigEndian()),
                  try cursor.readByte() == 0 else {
                throw TLS13HandshakeError.unsupportedCipherSuite(0)
            }
            let extensionsLength = Int(try cursor.readUInt16BigEndian())
            let extensions = try cursor.readSpan(count: extensionsLength)
            try cursor.requireFullyConsumed()
            let parsed = try parseServerExtensions(extensions)
            return TLS13ServerHello(
                random: random,
                keyShare: parsed.keyShare,
                cipherSuite: cipherSuite,
                selectedPreSharedKey: parsed.selectedPreSharedKey
            )
        } catch let error as TLS13HandshakeError {
            throw error
        } catch {
            throw .malformedMessage
        }
    }

    public static func makeEncryptedExtensions() throws(TLS13HandshakeError) -> OwnedBytes {
        var body = try Self.makeBuilder(maximumByteCount: 8, minimumCapacity: 2)
        do {
            try body.appendUInt16BigEndian(0)
            return finish(type: Self.encryptedExtensionsType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseEncryptedExtensions(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) {
        let body = try readBody(message, expectedType: Self.encryptedExtensionsType)
        var cursor = ByteCursor(body)
        do {
            let extensionLength = Int(try cursor.readUInt16BigEndian())
            guard extensionLength == cursor.remainingCount else {
                throw TLS13HandshakeError.malformedMessage
            }
            guard extensionLength == 0 else {
                throw TLS13HandshakeError.unsupportedExtension(0)
            }
            try cursor.requireFullyConsumed()
        } catch let error as TLS13HandshakeError {
            throw error
        } catch {
            throw .malformedMessage
        }
    }

    public static func makeCertificate(
        certificateDER: Span<UInt8>
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        guard certificateDER.count <= 0xFF_FFFF - 8 else { throw .malformedMessage }
        var body = try Self.makeBuilder(maximumByteCount: 16 * 1024 * 1024, minimumCapacity: certificateDER.count + 16)
        do {
            try body.append(0)
            try body.appendUInt24BigEndian(UInt32(certificateDER.count + 5))
            try body.appendUInt24BigEndian(UInt32(certificateDER.count))
            try body.append(certificateDER)
            try body.appendUInt16BigEndian(0)
            return finish(type: Self.certificateType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseCertificate(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> CertificateBytes {
        let body = try readBody(message, expectedType: Self.certificateType)
        var cursor = ByteCursor(body)
        do {
            guard try cursor.readByte() == 0 else { throw TLS13HandshakeError.malformedMessage }
            let listLength = Int(try cursor.readUInt24BigEndian())
            guard listLength == cursor.remainingCount else { throw TLS13HandshakeError.malformedMessage }
            let certificateLength = Int(try cursor.readUInt24BigEndian())
            let certificate = CertificateBytes(copying: try cursor.readSpan(count: certificateLength))
            guard try cursor.readUInt16BigEndian() == 0 else { throw TLS13HandshakeError.malformedMessage }
            try cursor.requireFullyConsumed()
            return certificate
        } catch {
            throw .malformedMessage
        }
    }

    public static func makeCertificateVerify(
        signature: Span<UInt8>
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        try makeCertificateVerify(
            signatureScheme: .ed25519,
            signature: signature
        )
    }

    public static func makeCertificateVerify(
        signatureScheme: TLS13SignatureScheme,
        signature: Span<UInt8>
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        guard !signature.isEmpty, signature.count <= UInt16.max else {
            throw .signatureFailure
        }
        var body = try Self.makeBuilder(
            maximumByteCount: Int(UInt16.max) + 4,
            minimumCapacity: signature.count + 4
        )
        do {
            try body.appendUInt16BigEndian(signatureScheme.rawValue)
            try body.appendUInt16BigEndian(UInt16(signature.count))
            try body.append(signature)
            return finish(type: Self.certificateVerifyType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseCertificateVerify(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        let parsed = try parseCertificateVerifyWithScheme(message)
        guard parsed.signatureScheme == .ed25519,
              parsed.signature.count == 64 else {
            throw .signatureFailure
        }
        return parsed.signature
    }

    public static func parseCertificateVerifyWithScheme(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> TLS13CertificateVerify {
        let body = try readBody(message, expectedType: Self.certificateVerifyType)
        var cursor = ByteCursor(body)
        do {
            guard let signatureScheme = TLS13SignatureScheme(
                rawValue: try cursor.readUInt16BigEndian()
            ) else {
                throw TLS13HandshakeError.signatureFailure
            }
            let signatureLength = Int(try cursor.readUInt16BigEndian())
            guard signatureLength > 0 else { throw TLS13HandshakeError.signatureFailure }
            let signature = OwnedBytes(copying: try cursor.readSpan(count: signatureLength))
            try cursor.requireFullyConsumed()
            return TLS13CertificateVerify(
                signatureScheme: signatureScheme,
                signature: signature
            )
        } catch {
            throw .malformedMessage
        }
    }

    public static func makeFinished(
        verifyData: Span<UInt8>
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        guard verifyData.count == 32 || verifyData.count == 48 else { throw .invalidFinished }
        return finish(type: Self.finishedType, body: OwnedBytes(copying: verifyData))
    }

    public static func parseFinished(
        _ message: Span<UInt8>,
        hashByteCount: Int
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        let body = try readBody(message, expectedType: Self.finishedType)
        guard body.count == hashByteCount else { throw .invalidFinished }
        return OwnedBytes(copying: body)
    }

    public static func makeKeyUpdate(
        requestUpdate: Bool
    ) throws(TLS13HandshakeError) -> OwnedBytes {
        var body = try Self.makeBuilder(maximumByteCount: 1, minimumCapacity: 1)
        do {
            try body.append(requestUpdate ? 1 : 0)
            return finish(type: Self.keyUpdateType, body: body.finish())
        } catch {
            throw .cryptographicFailure
        }
    }

    public static func parseKeyUpdate(
        _ message: Span<UInt8>
    ) throws(TLS13HandshakeError) -> Bool {
        let body = try readBody(message, expectedType: Self.keyUpdateType)
        guard body.count == 1 else { throw .malformedMessage }
        guard body[0] == 0 || body[0] == 1 else { throw .malformedMessage }
        return body[0] == 1
    }

    public static func splitMessages(
        _ bytes: Span<UInt8>
    ) throws(TLS13HandshakeError) -> ContiguousArray<OwnedBytes> {
        var cursor = ByteCursor(bytes)
        var result = ContiguousArray<OwnedBytes>()
        do {
            while !cursor.isAtEnd {
                guard cursor.remainingCount >= 4 else { throw TLS13HandshakeError.malformedMessage }
                let start = cursor.offset
                _ = try cursor.readByte()
                let length = Int(try cursor.readUInt24BigEndian())
                _ = try cursor.readSpan(count: length)
                let end = cursor.offset
                result.append(OwnedBytes(copying: bytes.extracting(start..<end)))
            }
            return result
        } catch {
            throw .malformedMessage
        }
    }

    private static func finish(type: UInt8, body: OwnedBytes) -> OwnedBytes {
        var output = ContiguousArray<UInt8>()
        output.reserveCapacity(4 + body.count)
        output.append(type)
        output.append(UInt8(truncatingIfNeeded: body.count >> 16))
        output.append(UInt8(truncatingIfNeeded: body.count >> 8))
        output.append(UInt8(truncatingIfNeeded: body.count))
        var bodyIndex = 0
        while bodyIndex < body.count {
            output.append(body[bodyIndex])
            bodyIndex += 1
        }
        return OwnedBytes(consuming: output)
    }

    private static func readBody(
        _ message: Span<UInt8>,
        expectedType: UInt8
    ) throws(TLS13HandshakeError) -> Span<UInt8> {
        guard message.count >= 4, message[0] == expectedType else {
            throw .unexpectedMessage(type: message.isEmpty ? 0 : message[0])
        }
        let length = (Int(message[1]) << 16) | (Int(message[2]) << 8) | Int(message[3])
        guard length == message.count - 4 else { throw .malformedMessage }
        return message.extracting(4..<message.count)
    }

    private static func appendSupportedVersionsClient(to builder: inout ByteBuilder) throws(ByteError) {
        try builder.appendUInt16BigEndian(0x002B)
        try builder.appendUInt16BigEndian(3)
        try builder.append(2)
        try builder.appendUInt16BigEndian(0x0304)
    }

    private static func appendSupportedVersionsServer(to builder: inout ByteBuilder) throws(ByteError) {
        try builder.appendUInt16BigEndian(0x002B)
        try builder.appendUInt16BigEndian(2)
        try builder.appendUInt16BigEndian(0x0304)
    }

    private static func appendKeyShare(
        to builder: inout ByteBuilder,
        keyShare: Span<UInt8>
    ) throws(ByteError) {
        try builder.appendUInt16BigEndian(0x0033)
        try builder.appendUInt16BigEndian(36)
        try builder.appendUInt16BigEndian(0x001D)
        try builder.appendUInt16BigEndian(32)
        try builder.append(keyShare)
    }

    private static func parseClientExtensions(
        _ bytes: Span<UInt8>
    ) throws(TLS13HandshakeError) -> (keyShare: OwnedBytes, preSharedKey: TLS13PreSharedKeyExtension?) {
        var cursor = ByteCursor(bytes)
        var keyShare: OwnedBytes?
        var preSharedKey: TLS13PreSharedKeyExtension?
        var sawPreSharedKey = false
        do {
            while !cursor.isAtEnd {
                let type = try cursor.readUInt16BigEndian()
                let length = Int(try cursor.readUInt16BigEndian())
                let value = try cursor.readSpan(count: length)
                guard !sawPreSharedKey else { throw TLS13HandshakeError.malformedMessage }
                switch type {
                case 0x002B:
                    guard value.count == 3, value[0] == 2, value[1] == 0x03, value[2] == 0x04 else { throw TLS13HandshakeError.malformedMessage }
                case 0x0033:
                    keyShare = try parseKeyShare(value)
                case TLS13PreSharedKeyExtension.extensionType:
                    preSharedKey = try TLS13PreSharedKeyExtension.parse(value)
                    sawPreSharedKey = true
                default:
                    throw TLS13HandshakeError.unsupportedExtension(type)
                }
            }
            guard let keyShare else { throw TLS13HandshakeError.invalidKeyShare }
            return (keyShare, preSharedKey)
        } catch let error as TLS13HandshakeError {
            throw error
        } catch let error as TLS13PSKError {
            _ = error
            throw .invalidPreSharedKey
        } catch {
            throw .malformedMessage
        }
    }

    private static func parseServerExtensions(
        _ bytes: Span<UInt8>
    ) throws(TLS13HandshakeError) -> (keyShare: OwnedBytes, selectedPreSharedKey: Bool) {
        var cursor = ByteCursor(bytes)
        var keyShare: OwnedBytes?
        var selectedPreSharedKey = false
        do {
            while !cursor.isAtEnd {
                let type = try cursor.readUInt16BigEndian()
                let length = Int(try cursor.readUInt16BigEndian())
                let value = try cursor.readSpan(count: length)
                switch type {
                case 0x002B:
                    guard value.count == 2, value[0] == 0x03, value[1] == 0x04 else { throw TLS13HandshakeError.malformedMessage }
                case 0x0033:
                    keyShare = try parseKeyShare(value)
                case TLS13PreSharedKeyExtension.extensionType:
                    guard value.count == 2, value[0] == 0, value[1] == 0 else {
                        throw TLS13HandshakeError.invalidPreSharedKey
                    }
                    guard !selectedPreSharedKey else { throw TLS13HandshakeError.invalidPreSharedKey }
                    selectedPreSharedKey = true
                default:
                    throw TLS13HandshakeError.unsupportedExtension(type)
                }
            }
            guard let keyShare else { throw TLS13HandshakeError.invalidKeyShare }
            return (keyShare, selectedPreSharedKey)
        } catch {
            throw .malformedMessage
        }
    }

    private static func parseKeyShare(_ value: Span<UInt8>) throws(TLS13HandshakeError) -> OwnedBytes {
        guard value.count == 36,
              value[0] == 0,
              value[1] == 0x1D,
              value[2] == 0,
              value[3] == 32 else {
            throw .invalidKeyShare
        }
        return OwnedBytes(copying: value.extracting(4..<36))
    }

    private static func makeBuilder(
        maximumByteCount: Int,
        minimumCapacity: Int
    ) throws(TLS13HandshakeError) -> ByteBuilder {
        do {
            return try ByteBuilder(
                maximumByteCount: maximumByteCount,
                minimumCapacity: minimumCapacity
            )
        } catch {
            throw .cryptographicFailure
        }
    }
}
