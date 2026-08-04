/// DTLS 1.2 security extensions required by the WebRTC profile.
public enum DTLSSecurityExtensions {
    /// RFC 7627 `extended_master_secret`.
    public static let extendedMasterSecret: UInt16 = 0x0017

    /// RFC 5746 `renegotiation_info`.
    public static let renegotiationInfo: UInt16 = 0xFF01

    /// Initial-handshake `renegotiation_info` has an empty renegotiated_connection.
    public static let initialRenegotiationInfoBody: [UInt8] = [0]
}
