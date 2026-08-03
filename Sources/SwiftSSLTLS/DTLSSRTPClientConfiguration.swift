import SwiftSSLCore

public struct DTLSSRTPClientConfiguration: Sendable, Hashable {
  public let protectionProfiles: ContiguousArray<DTLSSRTPProtectionProfile>
  public let masterKeyIdentifier: OwnedBytes
  public let requiresMasterKeyIdentifierEcho: Bool

  public init(
    protectionProfiles: ContiguousArray<DTLSSRTPProtectionProfile>,
    masterKeyIdentifier: Span<UInt8> = Span<UInt8>(),
    requiresMasterKeyIdentifierEcho: Bool = false
  ) throws(DTLSSRTPError) {
    try Self.validate(protectionProfiles)
    guard masterKeyIdentifier.count <= UInt8.max else {
      throw .masterKeyIdentifierTooLong(actual: masterKeyIdentifier.count)
    }
    guard !requiresMasterKeyIdentifierEcho || !masterKeyIdentifier.isEmpty else {
      throw .requiredMasterKeyIdentifierIsEmpty
    }
    self.protectionProfiles = protectionProfiles
    self.masterKeyIdentifier = OwnedBytes(copying: masterKeyIdentifier)
    self.requiresMasterKeyIdentifierEcho = requiresMasterKeyIdentifierEcho
  }

  private static func validate(
    _ profiles: ContiguousArray<DTLSSRTPProtectionProfile>
  ) throws(DTLSSRTPError) {
    guard !profiles.isEmpty else { throw .emptyProtectionProfileList }
    var seen = Set<DTLSSRTPProtectionProfile>()
    for profile in profiles {
      guard seen.insert(profile).inserted else {
        throw .duplicateProtectionProfile(profile)
      }
    }
  }
}
