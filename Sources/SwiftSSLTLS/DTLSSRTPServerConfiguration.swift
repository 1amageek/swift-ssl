public struct DTLSSRTPServerConfiguration: Sendable, Hashable {
  public let protectionProfiles: ContiguousArray<DTLSSRTPProtectionProfile>
  public let echoesMasterKeyIdentifier: Bool

  public init(
    protectionProfiles: ContiguousArray<DTLSSRTPProtectionProfile>,
    echoesMasterKeyIdentifier: Bool = true
  ) throws(DTLSSRTPError) {
    guard !protectionProfiles.isEmpty else {
      throw .emptyProtectionProfileList
    }
    var seen = Set<DTLSSRTPProtectionProfile>()
    for profile in protectionProfiles {
      guard seen.insert(profile).inserted else {
        throw .duplicateProtectionProfile(profile)
      }
    }
    self.protectionProfiles = protectionProfiles
    self.echoesMasterKeyIdentifier = echoesMasterKeyIdentifier
  }
}
