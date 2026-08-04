import SSLCore

/// Single-owner request sequencing. This value contains no shared mutable state.
package struct TLS13CapabilitySequencer: Sendable {
  package let engineIdentifier: OwnedBytes
  private var nextSequence: UInt64
  private var lastCompletedToken: TLS13CapabilityToken?

  package init(random: Span<UInt8>, role: TLSRole) {
    var identifier = ContiguousArray<UInt8>()
    identifier.reserveCapacity(random.count + 1)
    identifier.append(role == .client ? 0 : 1)
    var index = 0
    while index < random.count {
      identifier.append(random[index])
      index += 1
    }
    engineIdentifier = OwnedBytes(consuming: identifier)
    nextSequence = 0
    lastCompletedToken = nil
  }

  package mutating func issue(
    kind: TLS13CapabilityKind
  ) throws(TLS13CapabilityError) -> TLS13CapabilityToken {
    guard nextSequence != UInt64.max else { throw .sequenceExhausted }
    let token = TLS13CapabilityToken(
      engineIdentifier: engineIdentifier,
      sequence: nextSequence,
      kind: kind
    )
    nextSequence += 1
    return token
  }

  package borrowing func validate(
    _ response: borrowing TLS13CapabilityResponse,
    pending expected: TLS13CapabilityToken?
  ) throws(TLS13CapabilityError) {
    try validate(response.token, pending: expected)
    guard response.kind == response.token.kind else {
      throw .wrongKind(
        expected: response.token.kind,
        actual: response.kind
      )
    }
  }

  package borrowing func validate(
    _ token: TLS13CapabilityToken,
    pending expected: TLS13CapabilityToken?
  ) throws(TLS13CapabilityError) {
    guard token.engineIdentifier == engineIdentifier else {
      throw .wrongEngine(
        expected: engineIdentifier,
        actual: token.engineIdentifier
      )
    }
    guard let expected else {
      if token == lastCompletedToken {
        throw .duplicateResponse(token)
      }
      if token.sequence < nextSequence {
        throw .staleResponse(token)
      }
      throw .noPendingRequest
    }
    guard token.kind == expected.kind else {
      throw .wrongKind(expected: expected.kind, actual: token.kind)
    }
    guard token.sequence == expected.sequence else {
      if token.sequence < expected.sequence {
        throw .staleResponse(token)
      }
      throw .wrongSequence(
        expected: expected.sequence,
        actual: token.sequence
      )
    }
  }

  package mutating func complete(_ token: TLS13CapabilityToken) {
    lastCompletedToken = token
  }
}
import SSLTypes
