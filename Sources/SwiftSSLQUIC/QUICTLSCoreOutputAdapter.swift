import SwiftSSLCore
import SwiftSSLCrypto
import SwiftSSLTLS

package enum QUICTLSCoreOutputAdapter {
    package static func adapt(
        _ coreOutput: consuming TLS13HandshakeCoreOutput,
        role: TLSRole
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput {
        var coreOutput = consume coreOutput
        var actions = ContiguousArray<QUICTLSAction>()
        var order = ContiguousArray<QUICTLSEffectDescriptor>()
        var slots = QUICTrafficSecretSlots()

        do {
            while let effect = try coreOutput.nextEffect() {
                switch consume effect {
                case .action(let action):
                    let mapped = try mapAction(action)
                    actions.append(mapped)
                    order.append(.action(index: actions.count - 1))

                case .earlyTrafficSecret(let secret, let disposition):
                    if disposition == .application {
                        try appendEarlySecret(
                            secret,
                            role: role,
                            slots: &slots,
                            order: &order
                        )
                    }

                case .trafficSecrets(let epoch, let pair):
                    try appendSecrets(
                        pair,
                        epoch: epoch,
                        role: role,
                        slots: &slots,
                        order: &order
                    )
                }
            }
        } catch let error as TLS13HandshakeCoreOutputError {
            throw .coreOutput(error)
        } catch let error as QUICTLSHandshakeError {
            throw error
        } catch {
            throw .invalidState
        }

        let batch: QUICTLSActionBatch
        do {
            batch = try QUICTLSActionBatch(
                bytes: coreOutput.bytes,
                actions: actions
            )
        } catch let error {
            throw .byteOutput(error)
        }
        do {
            return try QUICTLSStepOutput(
                batch: batch,
                order: order,
                secrets: slots
            )
        } catch let error {
            throw .stepOutput(error)
        }
    }

    private static func mapAction(
        _ action: TLS13HandshakeCoreAction
    ) throws(QUICTLSHandshakeError) -> QUICTLSAction {
        switch action {
        case .emitHandshakeBytes(let epoch, let bytes):
            return .emitHandshakeBytes(level: try mapEpoch(epoch), bytes: bytes)
        case .handshakeComplete:
            return .handshakeComplete
        case .handshakeConfirmed:
            return .handshakeConfirmed
        case .earlyDataAccepted:
            return .earlyDataAccepted
        case .earlyDataRejected:
            return .earlyDataRejected
        case .installEarlyTrafficSecret, .installTrafficSecrets:
            throw .invalidState
        }
    }

    private static func appendSecrets(
        _ pair: consuming TLS13TrafficSecretPair,
        epoch: TLS13HandshakeEpoch,
        role: TLSRole,
        slots: inout QUICTrafficSecretSlots,
        order: inout ContiguousArray<QUICTLSEffectDescriptor>
    ) throws(QUICTLSHandshakeError) {
        let level: QUICTrafficSecretLevel
        switch epoch {
        case .handshake: level = .handshake
        case .application: level = .oneRTT
        case .initial, .earlyData: throw .unsupportedEpoch(epoch)
        }
        var pair = consume pair
        guard let clientSecret = pair.takeClientSecret(),
              let serverSecret = pair.takeServerSecret() else {
            throw .invalidState
        }
        let readSecret: SecretBytes
        let writeSecret: SecretBytes
        switch role {
        case .client:
            readSecret = consume serverSecret
            writeSecret = consume clientSecret
        case .server:
            readSecret = consume clientSecret
            writeSecret = consume serverSecret
        }
        let readEvent = QUICTrafficSecretEvent(
            direction: .read,
            level: level,
            cipherSuite: pair.cipherSuite,
            secret: readSecret
        )
        let writeEvent = QUICTrafficSecretEvent(
            direction: .write,
            level: level,
            cipherSuite: pair.cipherSuite,
            secret: writeSecret
        )
        do {
            try slots.insert(readEvent)
            try slots.insert(writeEvent)
        } catch let error {
            throw .stepOutput(error)
        }
        order.append(.trafficSecret(direction: .read, level: level))
        order.append(.trafficSecret(direction: .write, level: level))
    }

    private static func appendEarlySecret(
        _ secret: consuming TLS13EarlyTrafficSecret,
        role: TLSRole,
        slots: inout QUICTrafficSecretSlots,
        order: inout ContiguousArray<QUICTLSEffectDescriptor>
    ) throws(QUICTLSHandshakeError) {
        let direction: QUICSecretDirection
        switch role {
        case .client: direction = .write
        case .server: direction = .read
        }
        let cipherSuite = secret.cipherSuite
        let event = QUICTrafficSecretEvent(
            direction: direction,
            level: .zeroRTT,
            cipherSuite: cipherSuite,
            secret: secret.takeSecret()
        )
        do {
            try slots.insert(event)
        } catch let error {
            throw .stepOutput(error)
        }
        order.append(.trafficSecret(direction: direction, level: .zeroRTT))
    }

    private static func mapEpoch(
        _ epoch: TLS13HandshakeEpoch
    ) throws(QUICTLSHandshakeError) -> QUICHandshakeEncryptionLevel {
        switch epoch {
        case .initial: .initial
        case .earlyData: throw .unsupportedEpoch(epoch)
        case .handshake: .handshake
        case .application: .oneRTT
        }
    }
}
