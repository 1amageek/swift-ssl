/// DTLS `use_srtp` extension payload (RFC 5764 Section 4.1.1).
///
/// The wire value is independent of ClientHello/ServerHello context. A client
/// offers one or more profiles; a server response must contain exactly one. The
/// handshake state machines enforce that contextual rule and that the selected
/// profile was offered.

import P2PCoreBytes

/// An extensible 16-bit SRTP protection-profile registry value.
public struct SRTPProtectionProfile: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// AES-128 counter mode with an 80-bit HMAC-SHA1 authentication tag.
    public static let aes128CMHMACSHA180 = SRTPProtectionProfile(rawValue: 0x0001)

    /// AES-128 counter mode with a 32-bit RTP HMAC-SHA1 authentication tag.
    public static let aes128CMHMACSHA132 = SRTPProtectionProfile(rawValue: 0x0002)

    /// Null cipher with an 80-bit HMAC-SHA1 authentication tag.
    public static let nullHMACSHA180 = SRTPProtectionProfile(rawValue: 0x0005)

    /// Null cipher with a 32-bit RTP HMAC-SHA1 authentication tag.
    public static let nullHMACSHA132 = SRTPProtectionProfile(rawValue: 0x0006)
}

/// The encoded payload of TLS extension type 14 (`use_srtp`).
public struct DTLSUseSRTP: Sendable, Equatable {
    /// Profiles in descending preference order.
    public let protectionProfiles: [SRTPProtectionProfile]

    /// Master Key Identifier bytes. An empty value means that no MKI is used.
    public let mki: [UInt8]

    /// Creates a validated extension payload.
    public init(
        protectionProfiles: [SRTPProtectionProfile],
        mki: [UInt8] = []
    ) throws(DTLSWireError) {
        guard !protectionProfiles.isEmpty else {
            throw .dtls(.invalidFormat("use_srtp requires at least one protection profile"))
        }
        guard protectionProfiles.count <= Int(UInt16.max) / 2 else {
            throw .dtls(.invalidFormat("use_srtp protection-profile list is too large"))
        }
        for index in protectionProfiles.indices {
            guard !protectionProfiles[..<index].contains(protectionProfiles[index]) else {
                throw .dtls(.invalidFormat("use_srtp protection profiles must be unique"))
            }
        }
        guard mki.count <= Int(UInt8.max) else {
            throw .dtls(.invalidFormat("use_srtp MKI exceeds 255 bytes"))
        }
        self.protectionProfiles = protectionProfiles
        self.mki = mki
    }

    /// Encodes `SRTPProtectionProfiles<2..2^16-1> || srtp_mki<0..255>`.
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var profileWriter = ByteWriter()
        for profile in protectionProfiles {
            profileWriter.writeUInt16(profile.rawValue)
        }

        var writer = ByteWriter()
        try writer.dWriteVector16(profileWriter.finishArray())
        try writer.dWriteVector8(mki)
        return writer.finishArray()
    }

    /// Decodes and validates a `use_srtp` extension payload.
    public static func decode(from bytes: [UInt8]) throws(DTLSWireError) -> DTLSUseSRTP {
        var reader = ByteReader(bytes)
        let profileBytes = try reader.dReadVector16()
        guard profileBytes.count >= 2, profileBytes.count.isMultiple(of: 2) else {
            throw .dtls(.invalidFormat("use_srtp protection-profile vector must contain complete 16-bit values"))
        }

        var profileReader = ByteReader(profileBytes)
        var profiles: [SRTPProtectionProfile] = []
        profiles.reserveCapacity(profileBytes.count / 2)
        while !profileReader.isAtEnd {
            profiles.append(SRTPProtectionProfile(rawValue: try profileReader.dReadUInt16()))
        }

        let mki = try reader.dReadVector8()
        guard reader.isAtEnd else {
            throw .dtls(.invalidFormat("use_srtp extension contains trailing bytes"))
        }
        return try DTLSUseSRTP(protectionProfiles: profiles, mki: mki)
    }
}
