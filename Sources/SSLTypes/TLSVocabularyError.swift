/// Validation failures for bounded TLS vocabulary values.
public enum TLSVocabularyError: Error, Sendable, Equatable {
    case invalidLength(actual: Int)
}
