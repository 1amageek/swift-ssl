/// DTLS 1.2 ClientHello (RFC 6347 Section 4.2.1)
///
/// Same as TLS 1.2 ClientHello but with an additional cookie field for
/// DoS protection via HelloVerifyRequest exchange.
///
/// struct {
///   ProtocolVersion client_version;
///   Random random;
///   SessionID session_id;
///   opaque cookie<0..2^8-1>;           // DTLS-specific
///   CipherSuite cipher_suites<2..2^16-2>;
///   CompressionMethod compression_methods<1..2^8-1>;
///   Extension extensions<0..2^16-1>;   // optional
/// } ClientHello;

import NetworkingCore
import TLSWireCore
import TLSWireCore

/// DTLS 1.2 ClientHello message
public struct DTLSClientHello: Sendable {
    /// Client protocol version (DTLS 1.2 = 0xFEFD)
    public let clientVersion: DTLSVersion

    /// 32-byte client random
    public let random: [UInt8]

    /// Session ID (0-32 bytes, typically empty for new connections)
    public let sessionID: [UInt8]

    /// Cookie for DoS protection (from HelloVerifyRequest)
    public let cookie: [UInt8]

    /// Offered cipher suites
    public let cipherSuites: [DTLSCipherSuite]

    /// Supported elliptic curves (as extension data)
    public let supportedGroups: [NamedGroup]

    /// Supported signature algorithms
    public let signatureAlgorithms: [SignatureScheme]

    /// Offered SRTP profiles, or `nil` when this is an ordinary DTLS handshake.
    public let useSRTP: DTLSUseSRTP?

    /// Whether RFC 7627 extended master secret was offered.
    public let extendedMasterSecret: Bool

    /// Whether RFC 5746 secure renegotiation was offered.
    public let renegotiationInfo: Bool

    public init(
        clientVersion: DTLSVersion = .v1_2,
        random: [UInt8],
        sessionID: [UInt8] = [],
        cookie: [UInt8] = [],
        cipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        supportedGroups: [NamedGroup] = [.secp256r1],
        signatureAlgorithms: [SignatureScheme] = [.ecdsa_secp256r1_sha256],
        useSRTP: DTLSUseSRTP? = nil,
        extendedMasterSecret: Bool = true,
        renegotiationInfo: Bool = true
    ) {
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = sessionID
        self.cookie = cookie
        self.cipherSuites = cipherSuites
        self.supportedGroups = supportedGroups
        self.signatureAlgorithms = signatureAlgorithms
        self.useSRTP = useSRTP
        self.extendedMasterSecret = extendedMasterSecret
        self.renegotiationInfo = renegotiationInfo
    }

    /// Encode the ClientHello body (without handshake header)
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = TLSWireWriter()

        // client_version
        clientVersion.encode(writer: &writer)

        // random (32 bytes)
        writer.writeBytes(random)

        // session_id
        try writer.dWriteVector8(sessionID)

        // cookie (DTLS-specific)
        try writer.dWriteVector8(cookie)

        // cipher_suites
        var suitesWriter = TLSWireWriter()
        for suite in cipherSuites {
            suite.encode(writer: &suitesWriter)
        }
        try writer.dWriteVector16(suitesWriter.finishArray())

        // compression_methods (only null compression)
        try writer.dWriteVector8([0x00])

        // extensions
        var extWriter = TLSWireWriter()
        try encodeExtensions(writer: &extWriter)
        let extData = extWriter.finishArray()
        if !extData.isEmpty {
            try writer.dWriteVector16(extData)
        }

        return writer.finishArray()
    }

    private func encodeExtensions(writer: inout TLSWireWriter) throws(DTLSWireError) {
        // supported_groups extension (0x000A)
        if !supportedGroups.isEmpty {
            writer.writeUInt16(0x000A) // extension type
            var groupWriter = TLSWireWriter()
            var groupList = TLSWireWriter()
            for group in supportedGroups {
                groupList.writeUInt16(group.rawValue)
            }
            try groupWriter.dWriteVector16(groupList.finishArray())
            try writer.dWriteVector16(groupWriter.finishArray())
        }

        // signature_algorithms extension (0x000D)
        if !signatureAlgorithms.isEmpty {
            writer.writeUInt16(0x000D) // extension type
            var sigWriter = TLSWireWriter()
            var sigList = TLSWireWriter()
            for scheme in signatureAlgorithms {
                sigList.writeUInt16(scheme.rawValue)
            }
            try sigWriter.dWriteVector16(sigList.finishArray())
            try writer.dWriteVector16(sigWriter.finishArray())
        }

        // ec_point_formats extension (0x000B) — uncompressed only
        writer.writeUInt16(0x000B)
        var ecWriter = TLSWireWriter()
        try ecWriter.dWriteVector8([0x00]) // uncompressed
        try writer.dWriteVector16(ecWriter.finishArray())

        // use_srtp extension (14, RFC 5764).
        if let useSRTP {
            writer.writeUInt16(0x000E)
            try writer.dWriteVector16(useSRTP.encodeBytes())
        }

        if extendedMasterSecret {
            writer.writeUInt16(DTLSSecurityExtensions.extendedMasterSecret)
            try writer.dWriteVector16([])
        }

        if renegotiationInfo {
            writer.writeUInt16(DTLSSecurityExtensions.renegotiationInfo)
            try writer.dWriteVector16(DTLSSecurityExtensions.initialRenegotiationInfoBody)
        }
    }

    /// Decode a ClientHello from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> DTLSClientHello {
        var reader = TLSWireReader(data)

        let version = try DTLSVersion.decode(reader: &reader)
        let random = try reader.dReadBytes(32)
        let sessionID = try reader.dReadVector8()
        let cookie = try reader.dReadVector8()

        // cipher_suites
        let suitesData = try reader.dReadVector16()
        var suitesReader = TLSWireReader(suitesData)
        var suites: [DTLSCipherSuite] = []
        while !suitesReader.isAtEnd {
            let value = try suitesReader.dReadUInt16()
            if let suite = DTLSCipherSuite(rawValue: value) {
                suites.append(suite)
            }
        }

        // compression_methods (skip)
        _ = try reader.dReadVector8()

        // Parse extensions if present
        var groups: [NamedGroup] = []
        var sigAlgs: [SignatureScheme] = []
        var useSRTP: DTLSUseSRTP?
        var extendedMasterSecret = false
        var renegotiationInfo = false

        if !reader.isAtEnd {
            let extData = try reader.dReadVector16()
            var extReader = TLSWireReader(extData)
            while !extReader.isAtEnd {
                let extType = try extReader.dReadUInt16()
                let extBody = try extReader.dReadVector16()

                switch extType {
                case 0x000A: // supported_groups
                    var groupReader = TLSWireReader(extBody)
                    let groupList = try groupReader.dReadVector16()
                    var groupListReader = TLSWireReader(groupList)
                    while !groupListReader.isAtEnd {
                        let value = try groupListReader.dReadUInt16()
                        if let group = NamedGroup(rawValue: value) {
                            groups.append(group)
                        }
                    }
                case 0x000D: // signature_algorithms
                    var sigReader = TLSWireReader(extBody)
                    let sigList = try sigReader.dReadVector16()
                    var sigListReader = TLSWireReader(sigList)
                    while !sigListReader.isAtEnd {
                        let value = try sigListReader.dReadUInt16()
                        if let scheme = SignatureScheme(rawValue: value) {
                            sigAlgs.append(scheme)
                        }
                    }
                case 0x000E: // use_srtp
                    guard useSRTP == nil else {
                        throw DTLSWireError.dtls(.invalidFormat("Duplicate use_srtp extension"))
                    }
                    useSRTP = try DTLSUseSRTP.decode(from: extBody)
                case DTLSSecurityExtensions.extendedMasterSecret:
                    guard !extendedMasterSecret, extBody.isEmpty else {
                        throw DTLSWireError.dtls(.invalidFormat("Invalid or duplicate extended_master_secret extension"))
                    }
                    extendedMasterSecret = true
                case DTLSSecurityExtensions.renegotiationInfo:
                    guard !renegotiationInfo,
                          extBody == DTLSSecurityExtensions.initialRenegotiationInfoBody else {
                        throw DTLSWireError.dtls(.invalidFormat("Invalid or duplicate renegotiation_info extension"))
                    }
                    renegotiationInfo = true
                default:
                    break // skip unknown extensions
                }
            }
        }
        guard reader.isAtEnd else {
            throw DTLSWireError.dtls(.invalidFormat("ClientHello contains trailing bytes"))
        }

        return DTLSClientHello(
            clientVersion: version,
            random: random,
            sessionID: sessionID,
            cookie: cookie,
            cipherSuites: suites,
            supportedGroups: groups,
            signatureAlgorithms: sigAlgs,
            useSRTP: useSRTP,
            extendedMasterSecret: extendedMasterSecret,
            renegotiationInfo: renegotiationInfo
        )
    }
}
