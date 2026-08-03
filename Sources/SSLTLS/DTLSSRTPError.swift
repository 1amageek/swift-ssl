public enum DTLSSRTPError: Error, Sendable, Equatable {
  case emptyProtectionProfileList
  case duplicateProtectionProfile(DTLSSRTPProtectionProfile)
  case masterKeyIdentifierTooLong(actual: Int)
  case requiredMasterKeyIdentifierIsEmpty
  case unexpectedExtension
  case missingExtension
  case noSharedProtectionProfile
  case invalidServerSelection
  case selectedProtectionProfileWasNotOffered(DTLSSRTPProtectionProfile)
  case mismatchedMasterKeyIdentifier
  case negotiationNotEstablished
  case keySchedule(TLS13KeyScheduleError)
}
