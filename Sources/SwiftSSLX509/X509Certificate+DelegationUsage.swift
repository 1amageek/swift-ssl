import SwiftSSLASN1
import SwiftSSLCore

extension X509Certificate {
    /// Enforces the certificate authorization required by RFC 9345.
    public func validateDelegatedCredentialUsage()
        throws(X509DelegationUsageError)
    {
        let delegationUsageOID: ContiguousArray<UInt64> = [
            1, 3, 6, 1, 4, 1, 44363, 44,
        ]
        let keyUsageOID: ContiguousArray<UInt64> = [2, 5, 29, 15]
        var delegationUsage: X509Extension?
        var keyUsage: X509Extension?
        for extensionValue in extensions {
            if extensionValue.objectIdentifier == delegationUsageOID {
                guard delegationUsage == nil else {
                    throw .duplicateDelegationUsage
                }
                delegationUsage = extensionValue
            } else if extensionValue.objectIdentifier == keyUsageOID {
                keyUsage = extensionValue
            }
        }
        guard let delegationUsage else {
            throw .missingDelegationUsage
        }
        guard !delegationUsage.isCritical else {
            throw .criticalDelegationUsage
        }
        guard delegationUsage.value.count == 2,
            delegationUsage.value[0] == 0x05,
            delegationUsage.value[1] == 0x00
        else {
            throw .malformedDelegationUsage
        }
        guard let keyUsage else {
            throw .missingKeyUsage
        }

        let limits: ParsingLimits
        let budget: ParsingBudget
        do {
            limits = try ParsingLimits(
                maximumInputBytes: 64,
                maximumNestingDepth: 2,
                maximumElementCount: 2,
                maximumExtensionCount: 1,
                maximumOIDBytes: 16,
                maximumStringBytes: 16
            )
            budget = try ParsingBudget(
                limits: limits,
                inputByteCount: keyUsage.value.count
            )
        } catch {
            throw .malformedKeyUsage
        }
        var mutableBudget = budget
        var cursor = DERCursor(keyUsage.value.span)
        let element: DERElementView
        do {
            element = try cursor.readElement(using: &mutableBudget)
            try cursor.requireFullyConsumed()
        } catch {
            throw .malformedKeyUsage
        }
        let bits: DERBitString
        do {
            bits = try DERPrimitiveCodec.decodeBitString(from: element)
        } catch {
            throw .malformedKeyUsage
        }
        guard !bits.bytes.isEmpty, bits.bytes[0] & 0x80 != 0 else {
            throw .digitalSignatureRequired
        }
    }
}
