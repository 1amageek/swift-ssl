import SSLCore

/// The TLS 1.3 `pre_shared_key` extension value. The binder list is kept
/// separate from identities so a caller cannot accidentally bind a ticket to
/// a different identity or age.
public struct TLS13PreSharedKeyExtension: Sendable, Hashable {
    public static let extensionType: UInt16 = 0x0029
    public static let maximumVectorByteCount = 65_535

    public let identities: ContiguousArray<TLS13PSKIdentity>
    public let binders: ContiguousArray<TLS13PSKBinder>

    public init(
        identities: consuming ContiguousArray<TLS13PSKIdentity>,
        binders: consuming ContiguousArray<TLS13PSKBinder>
    ) throws(TLS13PSKError) {
        guard !identities.isEmpty,
              identities.count == binders.count else {
            throw .identityBinderCountMismatch
        }
        var identityIndex = 0
        while identityIndex < identities.count {
            var comparisonIndex = identityIndex + 1
            while comparisonIndex < identities.count {
                let firstIdentity = identities[identityIndex].identity
                let secondIdentity = identities[comparisonIndex].identity
                if ConstantTime.equal(
                    firstIdentity.span,
                    secondIdentity.span
                ) {
                    throw .duplicateIdentity
                }
                comparisonIndex += 1
            }
            identityIndex += 1
        }
        self.identities = identities
        self.binders = binders
    }

    public func encodedValue() throws(TLS13PSKError) -> OwnedBytes {
        var identityBytes = ContiguousArray<UInt8>()
        for identity in identities {
            guard identity.identity.count <= UInt16.max else {
                throw .invalidIdentityLength(identity.identity.count)
            }
            Self.appendUInt16(&identityBytes, UInt16(identity.identity.count))
            Self.append(&identityBytes, identity.identity.span)
            Self.appendUInt32(&identityBytes, identity.obfuscatedTicketAge)
        }
        guard identityBytes.count <= Self.maximumVectorByteCount else {
            throw .encodedLengthExceeded(identityBytes.count)
        }

        var binderBytes = ContiguousArray<UInt8>()
        for binder in binders {
            guard binder.value.count <= UInt8.max else {
                throw .invalidBinderLength(binder.value.count)
            }
            binderBytes.append(UInt8(binder.value.count))
            Self.append(&binderBytes, binder.value.span)
        }
        guard binderBytes.count <= Self.maximumVectorByteCount else {
            throw .encodedLengthExceeded(binderBytes.count)
        }

        var output = ContiguousArray<UInt8>()
        output.reserveCapacity(4 + identityBytes.count + binderBytes.count)
        Self.appendUInt16(&output, UInt16(identityBytes.count))
        output.append(contentsOf: identityBytes)
        Self.appendUInt16(&output, UInt16(binderBytes.count))
        output.append(contentsOf: binderBytes)
        guard output.count <= Self.maximumVectorByteCount else {
            throw .encodedLengthExceeded(output.count)
        }
        return OwnedBytes(consuming: output)
    }

    public static func parse(
        _ value: Span<UInt8>
    ) throws(TLS13PSKError) -> TLS13PreSharedKeyExtension {
        var cursor = ByteCursor(value)
        do {
            let identityLength = Int(try cursor.readUInt16BigEndian())
            let identitiesBytes = try cursor.readSpan(count: identityLength)
            let binderLength = Int(try cursor.readUInt16BigEndian())
            let bindersBytes = try cursor.readSpan(count: binderLength)
            try cursor.requireFullyConsumed()

            var identityCursor = ByteCursor(identitiesBytes)
            var identities = ContiguousArray<TLS13PSKIdentity>()
            while !identityCursor.isAtEnd {
                let length = Int(try identityCursor.readUInt16BigEndian())
                let identity = try identityCursor.readSpan(count: length)
                let age = try identityCursor.readUInt32BigEndian()
                identities.append(try TLS13PSKIdentity(identity: identity, obfuscatedTicketAge: age))
            }
            try identityCursor.requireFullyConsumed()

            var binderCursor = ByteCursor(bindersBytes)
            var binders = ContiguousArray<TLS13PSKBinder>()
            while !binderCursor.isAtEnd {
                let length = Int(try binderCursor.readByte())
                let binder = try binderCursor.readSpan(count: length)
                binders.append(try TLS13PSKBinder(value: binder))
            }
            try binderCursor.requireFullyConsumed()
            return try TLS13PreSharedKeyExtension(
                identities: consume identities,
                binders: consume binders
            )
        } catch let error as TLS13PSKError {
            throw error
        } catch {
            throw .malformedExtension
        }
    }

    private static func append(_ output: inout ContiguousArray<UInt8>, _ bytes: Span<UInt8>) {
        var index = 0
        while index < bytes.count {
            output.append(bytes[index])
            index += 1
        }
    }

    private static func appendUInt16(_ output: inout ContiguousArray<UInt8>, _ value: UInt16) {
        output.append(UInt8(truncatingIfNeeded: value >> 8))
        output.append(UInt8(truncatingIfNeeded: value))
    }

    private static func appendUInt32(_ output: inout ContiguousArray<UInt8>, _ value: UInt32) {
        output.append(UInt8(truncatingIfNeeded: value >> 24))
        output.append(UInt8(truncatingIfNeeded: value >> 16))
        output.append(UInt8(truncatingIfNeeded: value >> 8))
        output.append(UInt8(truncatingIfNeeded: value))
    }
}
