import SSLCore
import SSLCrypto
import SSLASN1

/// Modern password encryption for PKCS #8 private-key documents.
///
/// This profile deliberately supports only PBES2, PBKDF2-HMAC-SHA256, and
/// AES-256-GCM with a 128-bit authentication tag. Passwords are caller-owned
/// bytes; no Unicode conversion or legacy PKCS #12 password transform occurs.
public struct PBES2AES256GCM: PrivateKeyInfoEncryption, Sendable {
    public static let defaultEncryptionIterations: UInt32 = 600_000
    public static let defaultMinimumIterations: UInt32 = 100_000
    public static let defaultMaximumIterations: UInt32 = 10_000_000

    public let encryptionIterations: UInt32
    public let minimumAcceptedIterations: UInt32
    public let maximumAcceptedIterations: UInt32

    public init(
        encryptionIterations: UInt32 = Self.defaultEncryptionIterations,
        minimumAcceptedIterations: UInt32 = Self.defaultMinimumIterations,
        maximumAcceptedIterations: UInt32 = Self.defaultMaximumIterations
    ) throws(PBES2AES256GCMError) {
        guard minimumAcceptedIterations > 0,
              minimumAcceptedIterations <= encryptionIterations,
              encryptionIterations <= maximumAcceptedIterations else {
            throw .invalidConfiguration(
                minimum: minimumAcceptedIterations,
                maximum: maximumAcceptedIterations,
                encryptionIterations: encryptionIterations
            )
        }
        self.encryptionIterations = encryptionIterations
        self.minimumAcceptedIterations = minimumAcceptedIterations
        self.maximumAcceptedIterations = maximumAcceptedIterations
    }

    public func seal(
        _ privateKeyInfo: borrowing PrivateKeyInfo,
        password: Span<UInt8>,
        using entropy: borrowing any EntropySource
    ) throws -> EncryptedPrivateKeyInfo {
        guard !password.isEmpty else {
            throw PBES2AES256GCMError.emptyPassword
        }

        var salt = ContiguousArray<UInt8>(
            repeating: 0,
            count: EncryptedPrivateKeyInfo.saltByteCount
        )
        var nonce = ContiguousArray<UInt8>(
            repeating: 0,
            count: EncryptedPrivateKeyInfo.nonceByteCount
        )
        do {
            var saltDestination = salt.mutableSpan
            try entropy.fill(&saltDestination)
            var nonceDestination = nonce.mutableSpan
            try entropy.fill(&nonceDestination)
        } catch let error as EntropyError {
            throw PBES2AES256GCMError.entropy(error)
        }

        let (outputByteCount, overflow) = privateKeyInfo.derByteCount
            .addingReportingOverflow(AESGCM.tagByteCount)
        guard !overflow else {
            throw PBES2AES256GCMError.sizeOverflow
        }
        var ciphertextAndTag = ContiguousArray<UInt8>(
            repeating: 0,
            count: outputByteCount
        )

        try privateKeyInfo.withDERBytes {
            (plaintext: Span<UInt8>) throws -> Void in
            try withDerivedKey(
                password: password,
                salt: salt.span,
                iterations: encryptionIterations
            ) { key throws -> Void in
                let cipher: AESGCM
                do {
                    cipher = try AESGCM(key: key)
                } catch let error as AEADError {
                    throw PBES2AES256GCMError.authenticatedCipher(error)
                } catch {
                    preconditionFailure(
                        "AESGCM declares AEADError as its failure type"
                    )
                }
                var destination = ciphertextAndTag.mutableSpan
                let authenticatedData = ContiguousArray<UInt8>()
                do {
                    try cipher.seal(
                        plaintext: plaintext,
                        authenticatedData: authenticatedData.span,
                        nonce: nonce.span,
                        into: &destination
                    )
                } catch let error as AEADError {
                    throw PBES2AES256GCMError.authenticatedCipher(error)
                } catch {
                    preconditionFailure(
                        "AESGCM declares AEADError as its failure type"
                    )
                }
            }
        }

        let encodedDER: OwnedBytes
        do {
            encodedDER = try Self.encode(
                iterations: encryptionIterations,
                salt: salt.span,
                nonce: nonce.span,
                ciphertextAndTag: ciphertextAndTag.span
            )
        } catch let error as DERWriteError {
            throw PBES2AES256GCMError.derWrite(error)
        }
        do {
            return try EncryptedPrivateKeyInfo(consumingDER: encodedDER)
        } catch let error as EncryptedPrivateKeyInfoError {
            throw PBES2AES256GCMError.format(error)
        }
    }

    public func open(
        _ encryptedPrivateKeyInfo: borrowing EncryptedPrivateKeyInfo,
        password: Span<UInt8>
    ) throws -> PrivateKeyInfo {
        guard !password.isEmpty else {
            throw PBES2AES256GCMError.emptyPassword
        }
        let iterations = encryptedPrivateKeyInfo.iterationCount
        guard iterations >= minimumAcceptedIterations,
              iterations <= maximumAcceptedIterations else {
            throw PBES2AES256GCMError.iterationCountOutOfPolicy(
                minimum: minimumAcceptedIterations,
                maximum: maximumAcceptedIterations,
                actual: iterations
            )
        }

        let byteCount: SecretByteCount
        do {
            byteCount = try SecretByteCount(
                encryptedPrivateKeyInfo.plaintextByteCount
            )
        } catch let error as SecretMemoryError {
            throw PBES2AES256GCMError.secretMemory(error)
        } catch {
            preconditionFailure(
                "SecretByteCount declares SecretMemoryError as its failure type"
            )
        }

        let plaintext = try encryptedPrivateKeyInfo.withCryptographicInputs {
            (salt: Span<UInt8>, nonce: Span<UInt8>, ciphertext: Span<UInt8>)
                throws -> SecretBytes in
            try SecretBytes(byteCount: byteCount) { destination throws in
                try withDerivedKey(
                    password: password,
                    salt: salt,
                    iterations: iterations
                ) { key throws -> Void in
                    let cipher: AESGCM
                    do {
                        cipher = try AESGCM(key: key)
                    } catch let error as AEADError {
                        throw PBES2AES256GCMError.authenticatedCipher(error)
                    } catch {
                        preconditionFailure(
                            "AESGCM declares AEADError as its failure type"
                        )
                    }

                    let authenticatedData = ContiguousArray<UInt8>()
                    do {
                        try cipher.open(
                            ciphertextAndTag: ciphertext,
                            authenticatedData: authenticatedData.span,
                            nonce: nonce,
                            into: &destination
                        )
                    } catch AEADError.authenticationFailed {
                        throw PBES2AES256GCMError.authenticationFailed
                    } catch let error as AEADError {
                        throw PBES2AES256GCMError.authenticatedCipher(error)
                    } catch {
                        preconditionFailure(
                            "AESGCM declares AEADError as its failure type"
                        )
                    }
                }
            }
        }

        // Swift 6.4 cannot transfer a noncopyable SecretBytes owner through a
        // delegating throwing initializer without miscompiling SIL. Both the
        // source and destination are wipe-on-destroy owners, and the source is
        // destroyed immediately after this single import-boundary copy.
        return try plaintext.withBorrowedBytes {
            (bytes: Span<UInt8>) throws -> PrivateKeyInfo in
            do {
                return try PrivateKeyInfo(der: bytes)
            } catch let error as PrivateKeyInfoError {
                throw PBES2AES256GCMError.privateKey(error)
            }
        }
    }

    private func withDerivedKey<Result: ~Copyable>(
        password: Span<UInt8>,
        salt: Span<UInt8>,
        iterations: UInt32,
        _ body: (Span<UInt8>) throws -> Result
    ) throws -> Result {
        var key = SIMD32<UInt8>(repeating: 0)
        defer {
            withUnsafeMutableBytes(of: &key) { bytes in
                SecureWipe.erase(bytes.baseAddress!, byteCount: bytes.count)
            }
        }

        do {
            try withUnsafeMutableBytes(of: &key) {
                rawBytes throws(PBKDF2Error) in
                let pointer = rawBytes.baseAddress!
                    .assumingMemoryBound(to: UInt8.self)
                var destination = MutableSpan(
                    _unsafeStart: pointer,
                    count: EncryptedPrivateKeyInfo.derivedKeyByteCount
                )
                try PBKDF2HMACSHA256.deriveKey(
                    password: password,
                    salt: salt,
                    iterations: iterations,
                    into: &destination
                )
            }
        } catch let error as PBKDF2Error {
            throw PBES2AES256GCMError.keyDerivation(error)
        }

        return try withUnsafeBytes(of: &key) {
            rawBytes throws -> Result in
            try body(Span(_unsafeElements: rawBytes.bindMemory(to: UInt8.self)))
        }
    }

    private static func encode(
        iterations: UInt32,
        salt: Span<UInt8>,
        nonce: Span<UInt8>,
        ciphertextAndTag: Span<UInt8>
    ) throws(DERWriteError) -> OwnedBytes {
        let empty = ContiguousArray<UInt8>()
        let hmacSHA256OID = EncryptedPrivateKeyInfo.hmacSHA256OID
        let pbkdf2OID = EncryptedPrivateKeyInfo.pbkdf2OID
        let aes256GCMOID = EncryptedPrivateKeyInfo.aes256GCMOID
        let pbes2OID = EncryptedPrivateKeyInfo.pbes2OID

        var prf = try DERWriter(maximumByteCount: 64)
        try prf.appendObjectIdentifier(
            hmacSHA256OID.span
        )
        try prf.append(tag: Self.nullTag, content: empty.span)
        let prfBody = prf.finish()

        var kdfParameters = try DERWriter(maximumByteCount: 160)
        try kdfParameters.append(tag: Self.octetStringTag, content: salt)
        try kdfParameters.appendPositiveInteger(UInt64(iterations))
        try kdfParameters.appendPositiveInteger(
            UInt64(EncryptedPrivateKeyInfo.derivedKeyByteCount)
        )
        try kdfParameters.append(tag: Self.sequenceTag, content: prfBody.span)
        let kdfParametersBody = kdfParameters.finish()

        var keyDerivation = try DERWriter(maximumByteCount: 256)
        try keyDerivation.appendObjectIdentifier(
            pbkdf2OID.span
        )
        try keyDerivation.append(
            tag: Self.sequenceTag,
            content: kdfParametersBody.span
        )
        let keyDerivationBody = keyDerivation.finish()

        var gcmParameters = try DERWriter(maximumByteCount: 64)
        try gcmParameters.append(tag: Self.octetStringTag, content: nonce)
        try gcmParameters.appendPositiveInteger(
            UInt64(EncryptedPrivateKeyInfo.authenticationTagByteCount)
        )
        let gcmParametersBody = gcmParameters.finish()

        var encryptionScheme = try DERWriter(maximumByteCount: 128)
        try encryptionScheme.appendObjectIdentifier(
            aes256GCMOID.span
        )
        try encryptionScheme.append(
            tag: Self.sequenceTag,
            content: gcmParametersBody.span
        )
        let encryptionSchemeBody = encryptionScheme.finish()

        var pbes2Parameters = try DERWriter(maximumByteCount: 512)
        try pbes2Parameters.append(
            tag: Self.sequenceTag,
            content: keyDerivationBody.span
        )
        try pbes2Parameters.append(
            tag: Self.sequenceTag,
            content: encryptionSchemeBody.span
        )
        let pbes2ParametersBody = pbes2Parameters.finish()

        var encryptionAlgorithm = try DERWriter(maximumByteCount: 640)
        try encryptionAlgorithm.appendObjectIdentifier(
            pbes2OID.span
        )
        try encryptionAlgorithm.append(
            tag: Self.sequenceTag,
            content: pbes2ParametersBody.span
        )
        let encryptionAlgorithmBody = encryptionAlgorithm.finish()

        let (rootMaximum, overflow) = ciphertextAndTag.count
            .addingReportingOverflow(1_024)
        guard !overflow else {
            throw .invalidLength
        }
        var rootBody = try DERWriter(maximumByteCount: rootMaximum)
        try rootBody.append(
            tag: Self.sequenceTag,
            content: encryptionAlgorithmBody.span
        )
        try rootBody.append(
            tag: Self.octetStringTag,
            content: ciphertextAndTag
        )
        let rootContent = rootBody.finish()

        var root = try DERWriter(maximumByteCount: rootMaximum)
        try root.append(tag: Self.sequenceTag, content: rootContent.span)
        return root.finish()
    }

    private static let sequenceTag = DERTag(
        tagClass: .universal,
        isConstructed: true,
        number: 16
    )
    private static let octetStringTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 4
    )
    private static let nullTag = DERTag(
        tagClass: .universal,
        isConstructed: false,
        number: 5
    )
}
