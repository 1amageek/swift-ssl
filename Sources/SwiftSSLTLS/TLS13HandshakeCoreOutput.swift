import SwiftSSLCore

/// Ordered, record-independent effects produced by one TLS 1.3 state-machine
/// transition. All emitted message ranges borrow one owned byte allocation.
public struct TLS13HandshakeCoreOutput: ~Copyable, Sendable {
    public let bytes: OwnedBytes
    public let actions: ContiguousArray<TLS13HandshakeCoreAction>
    private var handshakeSecrets: TLS13TrafficSecretPair?
    private var applicationSecrets: TLS13TrafficSecretPair?
    private var nextActionIndex: Int

    package init(
        bytes: consuming OwnedBytes,
        actions: consuming ContiguousArray<TLS13HandshakeCoreAction>,
        handshakeSecrets: consuming TLS13TrafficSecretPair? = nil,
        applicationSecrets: consuming TLS13TrafficSecretPair? = nil
    ) throws(TLS13HandshakeCoreOutputError) {
        var index = 0
        while index < actions.count {
            if let range = actions[index].referencedByteRange,
               !bytes.contains(range) {
                throw .byteRange(.outOfBounds(
                    offset: range.offset,
                    requested: range.count,
                    available: Swift.max(0, bytes.count - range.offset)
                ))
            }
            index += 1
        }
        try Self.validateSecretReference(
            epoch: .initial,
            isStored: false,
            actions: actions
        )
        try Self.validateSecretReference(
            epoch: .handshake,
            isStored: handshakeSecrets != nil,
            actions: actions
        )
        try Self.validateSecretReference(
            epoch: .application,
            isStored: applicationSecrets != nil,
            actions: actions
        )
        self.bytes = consume bytes
        self.actions = consume actions
        self.handshakeSecrets = consume handshakeSecrets
        self.applicationSecrets = consume applicationSecrets
        nextActionIndex = 0
    }

    public var remainingEffectCount: Int {
        actions.count - nextActionIndex
    }

    public mutating func nextEffect()
        throws(TLS13HandshakeCoreOutputError) -> TLS13HandshakeCoreEffect?
    {
        guard nextActionIndex < actions.count else { return nil }
        let action = actions[nextActionIndex]
        nextActionIndex += 1
        guard case .installTrafficSecrets(let epoch) = action else {
            return .action(action)
        }
        switch epoch {
        case .handshake:
            guard let secrets = handshakeSecrets.take() else {
                throw .missingTrafficSecrets(epoch)
            }
            return .trafficSecrets(epoch: epoch, secrets: secrets)
        case .application:
            guard let secrets = applicationSecrets.take() else {
                throw .missingTrafficSecrets(epoch)
            }
            return .trafficSecrets(epoch: epoch, secrets: secrets)
        case .initial:
            throw .missingTrafficSecrets(epoch)
        }
    }

    private static func validateSecretReference(
        epoch: TLS13HandshakeEpoch,
        isStored: Bool,
        actions: borrowing ContiguousArray<TLS13HandshakeCoreAction>
    ) throws(TLS13HandshakeCoreOutputError) {
        var references = 0
        var index = 0
        while index < actions.count {
            if actions[index] == .installTrafficSecrets(epoch: epoch) {
                references += 1
            }
            index += 1
        }
        guard references <= 1 else { throw .duplicateTrafficSecrets(epoch) }
        if isStored, references == 0 { throw .unreferencedTrafficSecrets(epoch) }
        if !isStored, references != 0 { throw .missingTrafficSecrets(epoch) }
    }
}
