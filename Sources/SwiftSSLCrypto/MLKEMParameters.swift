struct MLKEMParameters: Sendable {
    static let mlKEM768 = MLKEMParameters(
        dimension: 3,
        eta1: 2,
        eta2: 2,
        du: 10,
        dv: 4,
        encapsulationKeyByteCount: 1_184,
        decapsulationKeyByteCount: 2_400,
        ciphertextByteCount: 1_088
    )

    static let mlKEM1024 = MLKEMParameters(
        dimension: 4,
        eta1: 2,
        eta2: 2,
        du: 11,
        dv: 5,
        encapsulationKeyByteCount: 1_568,
        decapsulationKeyByteCount: 3_168,
        ciphertextByteCount: 1_568
    )

    let dimension: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let encapsulationKeyByteCount: Int
    let decapsulationKeyByteCount: Int
    let ciphertextByteCount: Int

    var pkePrivateKeyByteCount: Int { 384 * dimension }
    var encodedVectorByteCount: Int { 384 * dimension }
    var compressedUByteCount: Int { 32 * du * dimension }
}
