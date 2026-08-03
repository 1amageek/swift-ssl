import SSLCore
import SSLCrypto

public enum TLS13RecordError: Error, Sendable, Equatable {
    case invalidTrafficSecretLength(expected: Int, actual: Int)
    case invalidContentLength(actual: Int)
    case invalidPaddingLength(actual: Int)
    case recordTooLarge(limit: Int, actual: Int)
    case outputTooSmall(required: Int, actual: Int)
    case malformedRecord
    case invalidOuterType(UInt8)
    case invalidLegacyVersion(UInt16)
    case authenticationFailed
    case aead(AEADError)
    case overlappingInputAndOutput
    case sequenceNumberExhausted
    case invalidKeyMaterial
    case keyDerivation(HKDFError)
    case secretMemory(SecretMemoryError)
}
