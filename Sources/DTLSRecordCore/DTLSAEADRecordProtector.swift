/// Package-internal DTLS 1.2 AES-GCM record protection over concrete operations.
///
/// Provider factories capture one concrete keyed AEAD in the operations below.
/// The protector itself is non-generic so normal WASM never invokes an associated-
/// type AEAD witness while sealing or opening a record.

import P2PCoreBytes
import P2PCoreCrypto

package struct DTLSAEADRecordProtector: Sendable {
    package typealias SealOperation = @Sendable (
        _ plaintext: [UInt8],
        _ nonce: [UInt8],
        _ aad: [UInt8]
    ) throws(CryptoError) -> [UInt8]

    package typealias OpenOperation = @Sendable (
        _ ciphertext: [UInt8],
        _ nonce: [UInt8],
        _ aad: [UInt8]
    ) throws(CryptoError) -> [UInt8]

    package let fixedIV: [UInt8]
    private let authenticationTagLength: Int
    private let sealOperation: SealOperation
    private let openOperation: OpenOperation

    package static var fixedIVLength: Int { 4 }
    package static var explicitNonceLength: Int { 8 }

    package init(
        fixedIV: [UInt8],
        authenticationTagLength: Int,
        seal: @escaping SealOperation,
        open: @escaping OpenOperation
    ) throws(DTLSRecordProtectionError) {
        guard fixedIV.count == Self.fixedIVLength else {
            throw .invalidFixedIVLength(
                expected: Self.fixedIVLength,
                actual: fixedIV.count
            )
        }
        self.fixedIV = fixedIV
        self.authenticationTagLength = authenticationTagLength
        self.sealOperation = seal
        self.openOperation = open
    }

    package func seal(
        plaintext: [UInt8],
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        guard explicitNonce.count == Self.explicitNonceLength else {
            throw .invalidExplicitNonceLength(
                expected: Self.explicitNonceLength,
                actual: explicitNonce.count
            )
        }

        var nonce = [UInt8](
            repeating: 0,
            count: fixedIV.count + explicitNonce.count
        )
        for index in fixedIV.indices {
            nonce[index] = fixedIV[index]
        }
        for index in explicitNonce.indices {
            nonce[fixedIV.count + index] = explicitNonce[index]
        }

        let sealed: [UInt8]
        do {
            sealed = try sealOperation(plaintext, nonce, aad)
        } catch {
            throw .crypto(error)
        }

        // Allocate the record fragment exactly once. Building this from a copied
        // nonce and then growing it asks Array to initialize from COW storage;
        // Swift 6.4 normal WASM rejects that path as an overlapping range.
        var output = [UInt8](
            repeating: 0,
            count: explicitNonce.count + sealed.count
        )
        for index in explicitNonce.indices {
            output[index] = explicitNonce[index]
        }
        for index in sealed.indices {
            output[explicitNonce.count + index] = sealed[index]
        }
        return output
    }

    package func open(
        ciphertext: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        let minimum = Self.explicitNonceLength + authenticationTagLength
        guard ciphertext.count >= minimum else {
            throw .ciphertextTooShort(minimum: minimum, actual: ciphertext.count)
        }

        let explicitNonce = Array(ciphertext[0..<Self.explicitNonceLength])
        let encryptedWithTag = Array(ciphertext[Self.explicitNonceLength...])
        var nonce = [UInt8](
            repeating: 0,
            count: fixedIV.count + explicitNonce.count
        )
        for index in fixedIV.indices {
            nonce[index] = fixedIV[index]
        }
        for index in explicitNonce.indices {
            nonce[fixedIV.count + index] = explicitNonce[index]
        }

        do {
            return try openOperation(encryptedWithTag, nonce, aad)
        } catch {
            throw .decryptionFailed
        }
    }
}
