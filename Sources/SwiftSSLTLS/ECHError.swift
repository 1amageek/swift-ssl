import SwiftSSLCrypto

/// Typed failures for RFC 9849 configuration and ClientHello protection.
public enum ECHError: Error, Sendable, Equatable {
  case malformedConfigList
  case malformedConfig
  case duplicateConfigExtension(UInt16)
  case invalidPublicName
  case unsupportedKEM(UInt16)
  case unsupportedCipherSuite(kdf: UInt16, aead: UInt16)
  case unsupportedMandatoryExtension(UInt16)
  case publicKeyMismatch
  case noCompatibleConfiguration
  case invalidClientHello
  case invalidOuterExtension
  case invalidPadding
  case payloadAuthenticationFailed
  case cryptographicFailure
  case hpke(HPKEError)
}
