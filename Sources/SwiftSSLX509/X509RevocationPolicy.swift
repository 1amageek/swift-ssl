public struct X509RevocationPolicy: Sendable, Hashable {
    public let mode: X509RevocationMode
    public let checksIntermediates: Bool
    public let ocspPolicy: OCSPValidationPolicy
    public let crlPolicy: X509CRLValidationPolicy

    public init(
        mode: X509RevocationMode,
        checksIntermediates: Bool = true,
        ocspPolicy: OCSPValidationPolicy = OCSPValidationPolicy(),
        crlPolicy: X509CRLValidationPolicy = X509CRLValidationPolicy()
    ) {
        self.mode = mode
        self.checksIntermediates = checksIntermediates
        self.ocspPolicy = ocspPolicy
        self.crlPolicy = crlPolicy
    }
}
