/// DTLS 1.2 ServerHello (RFC 5246 Section 7.4.1.3)
///
/// struct {
///   ProtocolVersion server_version;
///   Random random;
///   SessionID session_id;
///   CipherSuite cipher_suite;
///   CompressionMethod compression_method;
///   Extension extensions<0..2^16-1>;
/// } ServerHello;

import P2PCoreBytes

/// DTLS 1.2 ServerHello message
public struct DTLSServerHello: Sendable {
    /// Server protocol version
    public let serverVersion: DTLSVersion

    /// 32-byte server random
    public let random: [UInt8]

    /// Session ID
    public let sessionID: [UInt8]

    /// Selected cipher suite
    public let cipherSuite: DTLSCipherSuite

    /// Selected SRTP profile, or `nil` when SRTP was not negotiated.
    public let useSRTP: DTLSUseSRTP?

    /// Whether RFC 7627 extended master secret was negotiated.
    public let extendedMasterSecret: Bool

    /// Whether RFC 5746 secure renegotiation was negotiated.
    public let renegotiationInfo: Bool

    public init(
        serverVersion: DTLSVersion = .v1_2,
        random: [UInt8],
        sessionID: [UInt8] = [],
        cipherSuite: DTLSCipherSuite,
        useSRTP: DTLSUseSRTP? = nil,
        extendedMasterSecret: Bool = true,
        renegotiationInfo: Bool = true
    ) {
        self.serverVersion = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.useSRTP = useSRTP
        self.extendedMasterSecret = extendedMasterSecret
        self.renegotiationInfo = renegotiationInfo
    }

    /// Encode the ServerHello body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()

        serverVersion.encode(writer: &writer)
        writer.writeBytes(random)
        try writer.dWriteVector8(sessionID)
        cipherSuite.encode(writer: &writer)
        writer.writeUInt8(0x00) // compression_method: null

        // ec_point_formats extension
        var extWriter = ByteWriter()
        extWriter.writeUInt16(0x000B) // ec_point_formats
        var ecWriter = ByteWriter()
        try ecWriter.dWriteVector8([0x00]) // uncompressed
        try extWriter.dWriteVector16(ecWriter.finishArray())

        if let useSRTP {
            extWriter.writeUInt16(0x000E)
            try extWriter.dWriteVector16(useSRTP.encodeBytes())
        }

        if extendedMasterSecret {
            extWriter.writeUInt16(DTLSSecurityExtensions.extendedMasterSecret)
            try extWriter.dWriteVector16([])
        }

        if renegotiationInfo {
            extWriter.writeUInt16(DTLSSecurityExtensions.renegotiationInfo)
            try extWriter.dWriteVector16(DTLSSecurityExtensions.initialRenegotiationInfoBody)
        }

        try writer.dWriteVector16(extWriter.finishArray())

        return writer.finishArray()
    }

    /// Decode a ServerHello from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> DTLSServerHello {
        var reader = ByteReader(data)

        let version = try DTLSVersion.decode(reader: &reader)
        let random = try reader.dReadBytes(32)
        let sessionID = try reader.dReadVector8()
        let suite = try DTLSCipherSuite.decode(reader: &reader)
        _ = try reader.dReadUInt8() // compression_method

        var useSRTP: DTLSUseSRTP?
        var extendedMasterSecret = false
        var renegotiationInfo = false
        if !reader.isAtEnd {
            let extensionBytes = try reader.dReadVector16()
            var extensionReader = ByteReader(extensionBytes)
            while !extensionReader.isAtEnd {
                let extensionType = try extensionReader.dReadUInt16()
                let extensionBody = try extensionReader.dReadVector16()
                switch extensionType {
                case 0x000E:
                    guard useSRTP == nil else {
                        throw DTLSWireError.dtls(.invalidFormat("Duplicate use_srtp extension"))
                    }
                    useSRTP = try DTLSUseSRTP.decode(from: extensionBody)
                case DTLSSecurityExtensions.extendedMasterSecret:
                    guard !extendedMasterSecret, extensionBody.isEmpty else {
                        throw DTLSWireError.dtls(.invalidFormat("Invalid or duplicate extended_master_secret extension"))
                    }
                    extendedMasterSecret = true
                case DTLSSecurityExtensions.renegotiationInfo:
                    guard !renegotiationInfo,
                          extensionBody == DTLSSecurityExtensions.initialRenegotiationInfoBody else {
                        throw DTLSWireError.dtls(.invalidFormat("Invalid or duplicate renegotiation_info extension"))
                    }
                    renegotiationInfo = true
                default:
                    continue
                }
            }
        }
        guard reader.isAtEnd else {
            throw DTLSWireError.dtls(.invalidFormat("ServerHello contains trailing bytes"))
        }
        return DTLSServerHello(
            serverVersion: version,
            random: random,
            sessionID: sessionID,
            cipherSuite: suite,
            useSRTP: useSRTP,
            extendedMasterSecret: extendedMasterSecret,
            renegotiationInfo: renegotiationInfo
        )
    }
}
