/// TLS alert descriptions shared by stream, datagram, and QUIC profiles.
public enum TLSAlert: UInt8, Sendable, Hashable {
  case closeNotify = 0
  case unexpectedMessage = 10
  case badRecordMAC = 20
  case recordOverflow = 22
  case handshakeFailure = 40
  case badCertificate = 42
  case unsupportedCertificate = 43
  case certificateRevoked = 44
  case certificateExpired = 45
  case certificateUnknown = 46
  case illegalParameter = 47
  case unknownCA = 48
  case accessDenied = 49
  case decodeError = 50
  case decryptError = 51
  case protocolVersion = 70
  case insufficientSecurity = 71
  case internalError = 80
  case userCanceled = 90
  case missingExtension = 109
  case unsupportedExtension = 110
  case unrecognizedName = 112
  case badCertificateStatusResponse = 113
  case unknownPSKIdentity = 115
  case certificateRequired = 116
  case noApplicationProtocol = 120
  case echRequired = 121
}
