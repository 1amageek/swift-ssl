private enum SecureWipeProductionProbeFailure: Error {
    case intentional
}

@inline(never)
public func secureWipeFailureCleanupProbe() throws {
    let byteCount = try SecretByteCount(8)
    do {
        let secret = try SecretBytes(
            byteCount: byteCount
        ) { destination throws(SecureWipeProductionProbeFailure) in
            destination[0] = 0xA5
            throw .intentional
        }
        secret.withBorrowedBytes { _ in
            preconditionFailure("A failed secret initializer returned an owner")
        }
    } catch SecureWipeProductionProbeFailure.intentional {
        return
    }
}
