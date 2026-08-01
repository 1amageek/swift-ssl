import SwiftSSLCore

enum TLS13StreamCoreOutputAdapter {
    static func append(
        _ coreOutput: consuming TLS13HandshakeCoreOutput,
        role: TLSRole,
        recordBytes: inout ContiguousArray<UInt8>,
        terminalActions: inout ContiguousArray<TLSStreamAction>,
        handshakeRead: inout TLS13RecordProtector?,
        handshakeWrite: inout TLS13RecordProtector?,
        applicationRead: inout TLS13RecordProtector?,
        applicationWrite: inout TLS13RecordProtector?
    ) throws(TLS13HandshakeEngineError) {
        var coreOutput = consume coreOutput
        do {
            while let effect = try coreOutput.nextEffect() {
                switch consume effect {
                case .action(let action):
                    try append(
                        action,
                        bytes: coreOutput.bytes,
                        recordBytes: &recordBytes,
                        terminalActions: &terminalActions,
                        handshakeWrite: &handshakeWrite
                    )
                case .trafficSecrets(let epoch, let secrets):
                    try install(
                        secrets,
                        epoch: epoch,
                        role: role,
                        handshakeRead: &handshakeRead,
                        handshakeWrite: &handshakeWrite,
                        applicationRead: &applicationRead,
                        applicationWrite: &applicationWrite
                    )
                }
            }
        } catch let error as TLS13HandshakeEngineError {
            throw error
        } catch let error as TLS13HandshakeCoreOutputError {
            switch error {
            case .byteRange(let byteError): throw .output(byteError)
            case .duplicateTrafficSecrets, .missingTrafficSecrets,
                 .unreferencedTrafficSecrets: throw .invalidState
            }
        } catch let error as ByteError {
            throw .output(error)
        } catch {
            throw .malformedInput
        }
    }

    private static func append(
        _ action: TLS13HandshakeCoreAction,
        bytes: OwnedBytes,
        recordBytes: inout ContiguousArray<UInt8>,
        terminalActions: inout ContiguousArray<TLSStreamAction>,
        handshakeWrite: inout TLS13RecordProtector?
    ) throws(TLS13HandshakeEngineError) {
        switch action {
        case .emitHandshakeBytes(let epoch, let range):
            let emitted: Span<UInt8>
            do {
                emitted = try bytes.span(in: range)
            } catch let error {
                throw .output(error)
            }
            let messages = try TLS13HandshakeWire.handshakeMessageRanges(emitted)
            for messageRange in messages {
                let message = emitted.extracting(
                    messageRange.offset..<messageRange.endOffset
                )
                switch epoch {
                case .initial:
                    try TLS13HandshakeWire.appendPlaintextRecord(
                        message,
                        to: &recordBytes
                    )
                case .handshake:
                    guard var protector = handshakeWrite.take() else {
                        throw .invalidState
                    }
                    do {
                        try TLS13HandshakeWire.appendSealedRecord(
                            content: message,
                            contentType: .handshake,
                            with: &protector,
                            to: &recordBytes
                        )
                        handshakeWrite = consume protector
                    } catch let error {
                        handshakeWrite = consume protector
                        throw error
                    }
                case .application:
                    throw .invalidState
                }
            }
        case .installTrafficSecrets:
            throw .invalidState
        case .handshakeComplete:
            terminalActions.append(.handshakeComplete)
        case .handshakeConfirmed:
            terminalActions.append(.handshakeConfirmed)
        }
    }

    private static func install(
        _ pair: consuming TLS13TrafficSecretPair,
        epoch: TLS13HandshakeEpoch,
        role: TLSRole,
        handshakeRead: inout TLS13RecordProtector?,
        handshakeWrite: inout TLS13RecordProtector?,
        applicationRead: inout TLS13RecordProtector?,
        applicationWrite: inout TLS13RecordProtector?
    ) throws(TLS13HandshakeEngineError) {
        let pair = consume pair
        var readProtector: TLS13RecordProtector?
        var writeProtector: TLS13RecordProtector?
        do {
            switch role {
            case .client:
                readProtector = try pair.withServerSecret { secret throws(TLS13RecordError) in
                    try TLS13RecordProtector(
                        cipherSuite: pair.cipherSuite,
                        trafficSecret: secret
                    )
                }
                writeProtector = try pair.withClientSecret { secret throws(TLS13RecordError) in
                    try TLS13RecordProtector(
                        cipherSuite: pair.cipherSuite,
                        trafficSecret: secret
                    )
                }
            case .server:
                readProtector = try pair.withClientSecret { secret throws(TLS13RecordError) in
                    try TLS13RecordProtector(
                        cipherSuite: pair.cipherSuite,
                        trafficSecret: secret
                    )
                }
                writeProtector = try pair.withServerSecret { secret throws(TLS13RecordError) in
                    try TLS13RecordProtector(
                        cipherSuite: pair.cipherSuite,
                        trafficSecret: secret
                    )
                }
            }
        } catch let error {
            throw .record(error)
        }
        guard let readProtector = readProtector.take(),
              let writeProtector = writeProtector.take() else {
            throw .invalidState
        }
        switch epoch {
        case .initial:
            throw .invalidState
        case .handshake:
            guard handshakeRead == nil, handshakeWrite == nil else {
                throw .invalidState
            }
            handshakeRead = consume readProtector
            handshakeWrite = consume writeProtector
        case .application:
            guard applicationRead == nil, applicationWrite == nil else {
                throw .invalidState
            }
            applicationRead = consume readProtector
            applicationWrite = consume writeProtector
        }
    }
}
