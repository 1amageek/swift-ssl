import SSLCore

public struct DTLSSRTPUseSRTPData: Sendable, Hashable {
  public static let extensionType: UInt16 = 0x000E

  public let protectionProfileIDs: ContiguousArray<UInt16>
  public let masterKeyIdentifier: OwnedBytes

  public init(
    protectionProfiles: ContiguousArray<DTLSSRTPProtectionProfile>,
    masterKeyIdentifier: OwnedBytes
  ) {
    var profileIDs = ContiguousArray<UInt16>()
    profileIDs.reserveCapacity(protectionProfiles.count)
    for profile in protectionProfiles {
      profileIDs.append(profile.rawValue)
    }
    protectionProfileIDs = profileIDs
    self.masterKeyIdentifier = masterKeyIdentifier
  }

  package init(
    protectionProfileIDs: ContiguousArray<UInt16>,
    masterKeyIdentifier: OwnedBytes
  ) {
    self.protectionProfileIDs = protectionProfileIDs
    self.masterKeyIdentifier = masterKeyIdentifier
  }
}
