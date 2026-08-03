public enum AlgorithmPolicyError: Error, Sendable, Equatable {
  case unsupported(identifier: UInt16)
  case disallowed(identifier: UInt16)
  case experimentalNotEnabled(identifier: UInt16, revision: String)
}
