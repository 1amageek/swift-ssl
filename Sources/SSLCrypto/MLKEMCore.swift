import SSLCore

enum MLKEMCore {
  static func validateEncapsulationKey(
    _ bytes: Span<UInt8>,
    parameters: MLKEMParameters
  ) throws(KEMError) {
    guard bytes.count == parameters.encapsulationKeyByteCount else {
      throw .invalidPublicKeyLength(
        expected: parameters.encapsulationKeyByteCount,
        actual: bytes.count
      )
    }

    guard
      hasCanonicalEncodedVector(
        bytes.extracting(0..<parameters.encodedVectorByteCount)
      )
    else {
      throw .invalidPublicKeyEncoding
    }
  }

  static func validateDecapsulationKey(
    _ bytes: Span<UInt8>,
    parameters: MLKEMParameters
  ) throws(KEMError) {
    guard bytes.count == parameters.decapsulationKeyByteCount else {
      throw .invalidPrivateKeyLength(
        expected: parameters.decapsulationKeyByteCount,
        actual: bytes.count
      )
    }

    let pkePrivateKey = bytes.extracting(0..<parameters.pkePrivateKeyByteCount)
    guard hasCanonicalEncodedVector(pkePrivateKey) else {
      throw .invalidPrivateKeyEncoding
    }

    let publicKeyStart = parameters.pkePrivateKeyByteCount
    let publicKeyEnd = publicKeyStart + parameters.encapsulationKeyByteCount
    let publicKey = bytes.extracting(publicKeyStart..<publicKeyEnd)
    guard
      hasCanonicalEncodedVector(
        publicKey.extracting(0..<parameters.encodedVectorByteCount)
      )
    else {
      throw .invalidPrivateKeyEncoding
    }
    var hash = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var destination = hash.mutableSpan
    hash256(publicKey, into: &destination)
    let encodedHash = bytes.extracting(publicKeyEnd..<(publicKeyEnd + 32))
    guard constantTimeDifference(hash.span, encodedHash) == 0 else {
      throw .invalidPrivateKeyEncoding
    }
  }

  private static func hasCanonicalEncodedVector(_ bytes: Span<UInt8>) -> Bool {
    precondition(bytes.count.isMultiple(of: 3))
    var invalid: UInt32 = 0
    var offset = 0
    while offset < bytes.count {
      let first = UInt32(bytes[offset]) | (UInt32(bytes[offset + 1] & 0x0F) << 8)
      let second = UInt32(bytes[offset + 1] >> 4) | (UInt32(bytes[offset + 2]) << 4)
      invalid |= first >= UInt32(MLKEMArithmetic.modulus) ? 1 : 0
      invalid |= second >= UInt32(MLKEMArithmetic.modulus) ? 1 : 0
      offset += 3
    }
    return invalid == 0
  }

  static func keyGenerate(
    parameters: MLKEMParameters,
    d: Span<UInt8>,
    z: Span<UInt8>,
    encapsulationKey: inout MutableSpan<UInt8>,
    decapsulationKey: inout MutableSpan<UInt8>
  ) throws(KEMError) -> (
    publicKey: MLKEMExpandedPublicKey,
    privateKey: MLKEMExpandedPrivateKey
  ) {
    precondition(d.count == 32 && z.count == 32)
    precondition(encapsulationKey.count == parameters.encapsulationKeyByteCount)
    precondition(decapsulationKey.count == parameters.decapsulationKeyByteCount)

    var secretSampler = KeccakX2Core(sensitivity: .secret)
    let expanded = try hash512Secret(
      first: d,
      suffix: UInt8(parameters.dimension),
      using: &secretSampler
    )
    var matrix = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension * parameters.dimension,
      sensitivity: .publicData
    )
    var secretVector = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .secret
    )
    var errorVector = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .secret
    )
    var publicVector = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .publicData
    )

    try expanded.withBorrowedBytes { seeds throws(KEMError) in
      let rho = seeds.extracting(0..<32)
      let sigma = seeds.extracting(32..<64)
      sampleMatrix(rho: rho, parameters: parameters, into: &matrix)

      var nonce: UInt8 = 0
      sampleNoiseVectors(
        seed: sigma,
        eta: parameters.eta1,
        nonce: &nonce,
        first: &secretVector,
        second: &errorVector,
        sampler: &secretSampler
      )

      transformVectorForward(
        &secretVector,
        startingAt: 0,
        polynomialCount: parameters.dimension
      )
      transformVectorForward(
        &errorVector,
        startingAt: 0,
        polynomialCount: parameters.dimension
      )
      matrixVectorProduct(
        matrix: matrix,
        vector: secretVector,
        vectorOffset: 0,
        dimension: parameters.dimension,
        transposed: false,
        into: &publicVector
      )
      addVector(
        errorVector,
        addendOffset: 0,
        polynomialCount: parameters.dimension,
        into: &publicVector
      )

      var index = 0
      while index < parameters.dimension {
        publicVector.withPolynomial(at: index) { polynomial in
          encodePolynomial(
            polynomial,
            bitCount: 12,
            outputOffset: index * 384,
            into: &encapsulationKey
          )
        }
        secretVector.withPolynomial(at: index) { polynomial in
          encodePolynomial(
            polynomial,
            bitCount: 12,
            outputOffset: index * 384,
            into: &decapsulationKey
          )
        }
        index += 1
      }
      copy(
        rho,
        outputOffset: parameters.encodedVectorByteCount,
        into: &encapsulationKey
      )
    }

    copy(
      Span(_mutableSpan: encapsulationKey),
      outputOffset: parameters.pkePrivateKeyByteCount,
      into: &decapsulationKey
    )
    let publicKeyEnd =
      parameters.pkePrivateKeyByteCount
      + parameters.encapsulationKeyByteCount
    var hashOutput = decapsulationKey._mutatingExtracting(
      publicKeyEnd..<(publicKeyEnd + 32)
    )
    hash256(Span(_mutableSpan: encapsulationKey), into: &hashOutput)
    copy(z, outputOffset: publicKeyEnd + 32, into: &decapsulationKey)
    let expandedPublicKey = MLKEMExpandedPublicKey(
      consumingVector: consume publicVector,
      matrix: consume matrix,
      publicKeyHash: Span(_mutableSpan: decapsulationKey).extracting(
        publicKeyEnd..<(publicKeyEnd + 32)
      ),
      dimension: parameters.dimension
    )
    let expandedPrivateKey = try MLKEMExpandedPrivateKey(
      consumingSecretVector: consume secretVector,
      publicKey: expandedPublicKey,
      rejectionValue: z,
      parameters: parameters
    )
    return (expandedPublicKey, expandedPrivateKey)
  }

  static func expandEncapsulationKey(
    _ encapsulationKey: Span<UInt8>,
    parameters: MLKEMParameters
  ) throws(KEMError) -> MLKEMExpandedPublicKey {
    var publicKeyHash = ContiguousArray<UInt8>(repeating: 0, count: 32)
    var destination = publicKeyHash.mutableSpan
    hash256(encapsulationKey, into: &destination)
    return expandEncapsulationKey(
      encapsulationKey,
      publicKeyHash: publicKeyHash.span,
      parameters: parameters
    )
  }

  static func expandEncapsulationKey(
    _ encapsulationKey: Span<UInt8>,
    publicKeyHash: Span<UInt8>,
    parameters: MLKEMParameters
  ) -> MLKEMExpandedPublicKey {
    precondition(encapsulationKey.count == parameters.encapsulationKeyByteCount)
    precondition(publicKeyHash.count == 32)
    var publicVector = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .publicData
    )
    var matrix = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension * parameters.dimension,
      sensitivity: .publicData
    )
    var index = 0
    while index < parameters.dimension {
      publicVector.withMutablePolynomial(at: index) { polynomial in
        let start = index * 384
        MLKEMArithmetic.decode(
          encapsulationKey.extracting(start..<(start + 384)),
          bitCount: 12,
          into: &polynomial
        )
      }
      index += 1
    }
    let rho = encapsulationKey.extracting(
      parameters.encodedVectorByteCount..<parameters.encapsulationKeyByteCount
    )
    sampleMatrix(rho: rho, parameters: parameters, into: &matrix)
    return MLKEMExpandedPublicKey(
      consumingVector: consume publicVector,
      matrix: consume matrix,
      publicKeyHash: publicKeyHash,
      dimension: parameters.dimension
    )
  }

  static func encapsulate(
    parameters: MLKEMParameters,
    expandedPublicKey: borrowing MLKEMExpandedPublicKey,
    message: Span<UInt8>,
    ciphertext: inout MutableSpan<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    precondition(expandedPublicKey.dimension == parameters.dimension)
    precondition(message.count == 32)
    precondition(ciphertext.count == parameters.ciphertextByteCount)
    precondition(sharedSecret.count == 32)

    var secretSampler = KeccakX2Core(sensitivity: .secret)
    let keyAndRandomness = try expandedPublicKey.withHash {
      publicKeyHash throws(KEMError) in
      try hash512Secret(
        first: message,
        second: publicKeyHash,
        using: &secretSampler
      )
    }
    try keyAndRandomness.withBorrowedBytes { expanded throws(KEMError) in
      let candidateKey = expanded.extracting(0..<32)
      let randomness = expanded.extracting(32..<64)
      try encrypt(
        parameters: parameters,
        expandedPublicKey: expandedPublicKey,
        message: message,
        randomness: randomness,
        ciphertext: &ciphertext,
        noiseSampler: &secretSampler
      )
      copy(candidateKey, into: &sharedSecret)
    }
  }

  static func decapsulate(
    parameters: MLKEMParameters,
    expandedPrivateKey: borrowing MLKEMExpandedPrivateKey,
    ciphertext: Span<UInt8>,
    sharedSecret: inout MutableSpan<UInt8>
  ) throws(KEMError) {
    precondition(expandedPrivateKey.dimension == parameters.dimension)
    precondition(ciphertext.count == parameters.ciphertextByteCount)
    precondition(sharedSecret.count == 32)
    let expandedPublicKey = expandedPrivateKey.publicKey
    var secretSampler = KeccakX2Core(sensitivity: .secret)

    let message = try makeSecret(byteCount: 32) { output throws(KEMError) in
      decrypt(
        parameters: parameters,
        expandedPrivateKey: expandedPrivateKey,
        ciphertext: ciphertext,
        message: &output
      )
    }
    let candidate = try message.withBorrowedBytes { plaintext throws(KEMError) in
      try expandedPublicKey.withHash { publicKeyHash throws(KEMError) in
        try hash512Secret(
          first: plaintext,
          second: publicKeyHash,
          using: &secretSampler
        )
      }
    }
    let fallback = try expandedPrivateKey.withRejectionValue {
      rejectionValue throws(KEMError) in
      try shake256Secret(
        first: rejectionValue,
        second: ciphertext,
        using: &secretSampler
      )
    }
    let reencryption = try makeSecret(byteCount: parameters.ciphertextByteCount) {
      output throws(KEMError) in
      try message.withBorrowedBytes { plaintext throws(KEMError) in
        try candidate.withBorrowedBytes { expanded throws(KEMError) in
          try encrypt(
            parameters: parameters,
            expandedPublicKey: expandedPublicKey,
            message: plaintext,
            randomness: expanded.extracting(32..<64),
            ciphertext: &output,
            noiseSampler: &secretSampler
          )
        }
      }
    }

    var difference: UInt32 = 0
    defer {
      // Unsafe boundary invariants:
      // - difference is an initialized stack scalar exclusively borrowed here.
      // - The raw pointer is valid for exactly MemoryLayout<UInt32>.size bytes.
      // - No pointer escapes and the value is not accessed during the erase.
      withUnsafeMutablePointer(to: &difference) { pointer in
        SecureWipe.erase(
          UnsafeMutableRawPointer(pointer),
          byteCount: MemoryLayout<UInt32>.size
        )
      }
    }
    reencryption.withBorrowedBytes { expected in
      difference = constantTimeDifference(ciphertext, expected)
    }
    let nonZero = (difference | (0 &- difference)) >> 31
    let rejectionMask = UInt8(truncatingIfNeeded: 0 &- nonZero)
    try candidate.withBorrowedBytes { expanded throws(KEMError) in
      let candidateKey = expanded.extracting(0..<32)
      fallback.withBorrowedBytes { fallbackKey in
        var index = 0
        while index < 32 {
          sharedSecret[index] =
            (candidateKey[index] & ~rejectionMask)
            | (fallbackKey[index] & rejectionMask)
          index += 1
        }
      }
    }
  }

  private static func encrypt(
    parameters: MLKEMParameters,
    expandedPublicKey: borrowing MLKEMExpandedPublicKey,
    message: Span<UInt8>,
    randomness: Span<UInt8>,
    ciphertext: inout MutableSpan<UInt8>,
    noiseSampler: inout KeccakX2Core
  ) throws(KEMError) {
    precondition(expandedPublicKey.dimension == parameters.dimension)
    var noise = MLKEMPolynomialStorage(
      polynomialCount: 2 * parameters.dimension + 1,
      sensitivity: .secret
    )
    var u = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .publicData
    )
    var v = MLKEMPolynomialStorage(
      polynomialCount: 1,
      sensitivity: .publicData
    )

    var nonce: UInt8 = 0
    precondition(parameters.eta1 == parameters.eta2)
    sampleNoise(
      seed: randomness,
      eta: parameters.eta1,
      startingAt: 0,
      polynomialCount: 2 * parameters.dimension + 1,
      nonce: &nonce,
      into: &noise,
      sampler: &noiseSampler
    )

    transformVectorForward(
      &noise,
      startingAt: 0,
      polynomialCount: parameters.dimension
    )
    expandedMatrixVectorProduct(
      publicKey: expandedPublicKey,
      vector: noise,
      vectorOffset: 0,
      dimension: parameters.dimension,
      transposed: true,
      into: &u
    )
    var inverseIndex = 0
    while inverseIndex < parameters.dimension {
      u.withMutablePolynomial(at: inverseIndex) { output in
        noise.withPolynomial(at: parameters.dimension + inverseIndex) { errorPolynomial in
          MLKEMArithmetic.inverseNTT(&output, adding: errorPolynomial)
        }
      }
      inverseIndex += 1
    }

    v.withMutablePolynomial(at: 0) { output in
      var coordinate = 0
      while coordinate < parameters.dimension {
        expandedPublicKey.withVectorPolynomial(at: coordinate) { publicPolynomial in
          noise.withPolynomial(at: coordinate) { ephemeralPolynomial in
            MLKEMArithmetic.multiplyNTTs(
              publicPolynomial,
              ephemeralPolynomial,
              accumulatingInto: &output,
              initialize: coordinate == 0
            )
          }
        }
        coordinate += 1
      }
      noise.withPolynomial(at: 2 * parameters.dimension) { errorPolynomial in
        MLKEMArithmetic.inverseNTT(&output, adding: errorPolynomial)
      }
      var coefficient = 0
      while coefficient < 256 {
        let bit = MLKEMArithmetic.Coefficient(
          (message[coefficient / 8] >> UInt8(coefficient & 7)) & 1
        )
        output[coefficient] = MLKEMArithmetic.add(
          output[coefficient],
          MLKEMArithmetic.decompress(bit, bitCount: 1)
        )
        coefficient += 1
      }
    }

    var index = 0
    while index < parameters.dimension {
      u.withPolynomial(at: index) { polynomial in
        encodeCompressedPolynomial(
          polynomial,
          bitCount: parameters.du,
          outputOffset: index * 32 * parameters.du,
          into: &ciphertext
        )
      }
      index += 1
    }
    v.withPolynomial(at: 0) { polynomial in
      encodeCompressedPolynomial(
        polynomial,
        bitCount: parameters.dv,
        outputOffset: parameters.compressedUByteCount,
        into: &ciphertext
      )
    }
  }

  private static func decrypt(
    parameters: MLKEMParameters,
    expandedPrivateKey: borrowing MLKEMExpandedPrivateKey,
    ciphertext: Span<UInt8>,
    message: inout MutableSpan<UInt8>
  ) {
    var u = MLKEMPolynomialStorage(
      polynomialCount: parameters.dimension,
      sensitivity: .publicData
    )
    var v = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .publicData)
    var product = MLKEMPolynomialStorage(polynomialCount: 1, sensitivity: .secret)

    var index = 0
    while index < parameters.dimension {
      u.withMutablePolynomial(at: index) { polynomial in
        let start = index * 32 * parameters.du
        MLKEMArithmetic.decodeDecompressed(
          ciphertext.extracting(start..<(start + 32 * parameters.du)),
          bitCount: parameters.du,
          into: &polynomial
        )
        MLKEMArithmetic.forwardNTT(&polynomial)
      }
      index += 1
    }
    v.withMutablePolynomial(at: 0) { polynomial in
      MLKEMArithmetic.decodeDecompressed(
        ciphertext.extracting(parameters.compressedUByteCount..<ciphertext.count),
        bitCount: parameters.dv,
        into: &polynomial
      )
    }

    product.withMutablePolynomial(at: 0) { output in
      var coordinate = 0
      while coordinate < parameters.dimension {
        expandedPrivateKey.withSecretPolynomial(at: coordinate) { secretPolynomial in
          u.withPolynomial(at: coordinate) { uPolynomial in
            MLKEMArithmetic.multiplyNTTs(
              secretPolynomial,
              uPolynomial,
              accumulatingInto: &output,
              initialize: coordinate == 0
            )
          }
        }
        coordinate += 1
      }
      MLKEMArithmetic.inverseNTT(&output)
    }

    v.withMutablePolynomial(at: 0) { recovered in
      product.withPolynomial(at: 0) { innerProduct in
        MLKEMArithmetic.subtract(innerProduct, from: &recovered)
      }
      MLKEMArithmetic.encodeCompressed(
        Span(_mutableSpan: recovered),
        bitCount: 1,
        into: &message
      )
    }
  }

  private static func sampleMatrix(
    rho: Span<UInt8>,
    parameters: MLKEMParameters,
    into matrix: inout MLKEMPolynomialStorage
  ) {
    let polynomialCount = parameters.dimension * parameters.dimension
    var sampler = KeccakX2Core(sensitivity: .publicData)
    var index = 0
    while index + 2 <= polynomialCount {
      let first = matrixSuffix(at: index, dimension: parameters.dimension)
      let second = matrixSuffix(at: index + 1, dimension: parameters.dimension)
      sampler.reset(
        seed: rho,
        firstSuffix: first,
        secondSuffix: second
      )
      matrix.withTwoMutablePolynomials(startingAt: index) {
        firstPolynomial,
        secondPolynomial in
        sampler.sampleNTT(
          first: &firstPolynomial,
          second: &secondPolynomial
        )
      }
      index += 2
    }

    if index < polynomialCount {
      let suffix = matrixSuffix(at: index, dimension: parameters.dimension)
      sampler.reset(
        seed: rho,
        firstSuffix: suffix,
        secondSuffix: suffix
      )
      matrix.withMutablePolynomial(at: index) { polynomial in
        sampler.sampleNTT(into: &polynomial)
      }
    }
  }

  private static func sampleNoise(
    seed: Span<UInt8>,
    eta: Int,
    startingAt startIndex: Int,
    polynomialCount: Int,
    nonce: inout UInt8,
    into storage: inout MLKEMPolynomialStorage,
    sampler: inout KeccakX2Core
  ) {
    precondition(seed.count == 32 && eta == 2)
    precondition(
      startIndex >= 0 && polynomialCount >= 0
        && startIndex + polynomialCount <= storage.polynomialCount
    )

    let endIndex = startIndex + polynomialCount
    var index = startIndex
    while index + 2 <= endIndex {
      sampler.reset(
        secretSeed: seed,
        firstNonce: nonce,
        secondNonce: nonce &+ 1
      )
      storage.withTwoMutablePolynomials(startingAt: index) {
        first,
        second in
        sampler.sampleCBDEta2(
          first: &first,
          second: &second
        )
      }
      nonce &+= 2
      index += 2
    }

    if index < endIndex {
      sampler.reset(
        secretSeed: seed,
        firstNonce: nonce,
        secondNonce: nonce
      )
      storage.withMutablePolynomial(at: index) { polynomial in
        sampler.sampleCBDEta2(into: &polynomial)
      }
      nonce &+= 1
    }
  }

  private static func sampleNoiseVectors(
    seed: Span<UInt8>,
    eta: Int,
    nonce: inout UInt8,
    first: inout MLKEMPolynomialStorage,
    second: inout MLKEMPolynomialStorage,
    sampler: inout KeccakX2Core
  ) {
    precondition(seed.count == 32 && eta == 2)
    precondition(first.polynomialCount == second.polynomialCount)

    let firstCount = first.polynomialCount
    let totalCount = firstCount + second.polynomialCount
    var index = 0
    while index + 2 <= totalCount {
      sampler.reset(
        secretSeed: seed,
        firstNonce: nonce,
        secondNonce: nonce &+ 1
      )
      if index + 2 <= firstCount {
        first.withTwoMutablePolynomials(startingAt: index) {
          firstPolynomial,
          secondPolynomial in
          sampler.sampleCBDEta2(
            first: &firstPolynomial,
            second: &secondPolynomial
          )
        }
      } else if index < firstCount {
        first.withMutablePolynomial(at: index) { firstPolynomial in
          second.withMutablePolynomial(at: 0) { secondPolynomial in
            sampler.sampleCBDEta2(
              first: &firstPolynomial,
              second: &secondPolynomial
            )
          }
        }
      } else {
        second.withTwoMutablePolynomials(startingAt: index - firstCount) {
          firstPolynomial,
          secondPolynomial in
          sampler.sampleCBDEta2(
            first: &firstPolynomial,
            second: &secondPolynomial
          )
        }
      }
      nonce &+= 2
      index += 2
    }
    precondition(index == totalCount)
  }

  @inline(__always)
  private static func matrixSuffix(at index: Int, dimension: Int) -> (UInt8, UInt8) {
    precondition(index >= 0 && index < dimension * dimension)
    return (UInt8(index % dimension), UInt8(index / dimension))
  }

  private static func matrixVectorProduct(
    matrix: borrowing MLKEMPolynomialStorage,
    vector: borrowing MLKEMPolynomialStorage,
    vectorOffset: Int,
    dimension: Int,
    transposed: Bool,
    into output: inout MLKEMPolynomialStorage
  ) {
    precondition(vectorOffset >= 0 && vectorOffset + dimension <= vector.polynomialCount)
    precondition(output.polynomialCount == dimension)
    var row = 0
    while row < dimension {
      output.withMutablePolynomial(at: row) { destination in
        var column = 0
        while column < dimension {
          let matrixIndex =
            transposed
            ? column * dimension + row
            : row * dimension + column
          matrix.withPolynomial(at: matrixIndex) { matrixPolynomial in
            vector.withPolynomial(at: vectorOffset + column) { vectorPolynomial in
              MLKEMArithmetic.multiplyNTTs(
                matrixPolynomial,
                vectorPolynomial,
                accumulatingInto: &destination,
                initialize: column == 0
              )
            }
          }
          column += 1
        }
      }
      row += 1
    }
  }

  private static func expandedMatrixVectorProduct(
    publicKey: borrowing MLKEMExpandedPublicKey,
    vector: borrowing MLKEMPolynomialStorage,
    vectorOffset: Int,
    dimension: Int,
    transposed: Bool,
    into output: inout MLKEMPolynomialStorage
  ) {
    precondition(publicKey.dimension == dimension)
    precondition(vectorOffset >= 0 && vectorOffset + dimension <= vector.polynomialCount)
    precondition(output.polynomialCount == dimension)
    var row = 0
    while row < dimension {
      output.withMutablePolynomial(at: row) { destination in
        var column = 0
        while column < dimension {
          let matrixIndex =
            transposed
            ? column * dimension + row
            : row * dimension + column
          publicKey.withMatrixPolynomial(at: matrixIndex) { matrixPolynomial in
            vector.withPolynomial(at: vectorOffset + column) { vectorPolynomial in
              MLKEMArithmetic.multiplyNTTs(
                matrixPolynomial,
                vectorPolynomial,
                accumulatingInto: &destination,
                initialize: column == 0
              )
            }
          }
          column += 1
        }
      }
      row += 1
    }
  }

  private static func addVector(
    _ addend: borrowing MLKEMPolynomialStorage,
    addendOffset: Int,
    polynomialCount: Int,
    into output: inout MLKEMPolynomialStorage
  ) {
    precondition(
      addendOffset >= 0 && polynomialCount >= 0
        && addendOffset + polynomialCount <= addend.polynomialCount
        && output.polynomialCount == polynomialCount
    )
    var index = 0
    while index < polynomialCount {
      output.withMutablePolynomial(at: index) { destination in
        addend.withPolynomial(at: addendOffset + index) { source in
          MLKEMArithmetic.add(source, into: &destination)
        }
      }
      index += 1
    }
  }

  private static func transformVectorForward(
    _ vector: inout MLKEMPolynomialStorage,
    startingAt startIndex: Int,
    polynomialCount: Int
  ) {
    precondition(
      startIndex >= 0 && polynomialCount >= 0
        && startIndex + polynomialCount <= vector.polynomialCount
    )
    let endIndex = startIndex + polynomialCount
    var index = startIndex
    while index < endIndex {
      vector.withMutablePolynomial(at: index) { MLKEMArithmetic.forwardNTT(&$0) }
      index += 1
    }
  }

  private static func encodePolynomial(
    _ polynomial: Span<MLKEMArithmetic.Coefficient>,
    bitCount: Int,
    outputOffset: Int,
    into output: inout MutableSpan<UInt8>
  ) {
    var destination = output._mutatingExtracting(
      outputOffset..<(outputOffset + 32 * bitCount)
    )
    MLKEMArithmetic.encode(polynomial, bitCount: bitCount, into: &destination)
  }

  private static func encodeCompressedPolynomial(
    _ polynomial: Span<MLKEMArithmetic.Coefficient>,
    bitCount: Int,
    outputOffset: Int,
    into output: inout MutableSpan<UInt8>
  ) {
    var destination = output._mutatingExtracting(
      outputOffset..<(outputOffset + 32 * bitCount)
    )
    MLKEMArithmetic.encodeCompressed(
      polynomial,
      bitCount: bitCount,
      into: &destination
    )
  }

  private static func copy(
    _ input: Span<UInt8>,
    outputOffset: Int = 0,
    into output: inout MutableSpan<UInt8>
  ) {
    precondition(outputOffset >= 0 && outputOffset + input.count <= output.count)
    var index = 0
    while index < input.count {
      output[outputOffset + index] = input[index]
      index += 1
    }
  }

  private static func hash256(
    _ input: Span<UInt8>,
    into output: inout MutableSpan<UInt8>
  ) {
    var context = KeccakX2Core(sensitivity: .publicData)
    context.sha3_256(input, into: &output)
  }

  private static func hash512Secret(
    first: Span<UInt8>,
    second: Span<UInt8>,
    using context: inout KeccakX2Core
  ) throws(KEMError) -> SecretBytes {
    try makeSecret(byteCount: 64) { output throws(KEMError) in
      context.sha3_512(first: first, second: second, into: &output)
    }
  }

  private static func hash512Secret(
    first: Span<UInt8>,
    suffix: UInt8,
    using context: inout KeccakX2Core
  ) throws(KEMError) -> SecretBytes {
    try makeSecret(byteCount: 64) { output throws(KEMError) in
      context.sha3_512(first: first, suffix: suffix, into: &output)
    }
  }

  private static func shake256Secret(
    first: Span<UInt8>,
    second: Span<UInt8>,
    using context: inout KeccakX2Core
  ) throws(KEMError) -> SecretBytes {
    try makeSecret(byteCount: 32) { output throws(KEMError) in
      context.shake256(first: first, second: second, into: &output)
    }
  }

  private static func mapPrimitiveFailure(
    _ operation: () throws(CryptoInputError) -> Void
  ) throws(KEMError) {
    do {
      try operation()
    } catch {
      throw .primitiveFailure(error)
    }
  }

  private static func makeSecret(
    byteCount: Int,
    initializer: (inout MutableSpan<UInt8>) throws(KEMError) -> Void
  ) throws(KEMError) -> SecretBytes {
    let validatedCount: SecretByteCount
    do {
      validatedCount = try SecretByteCount(byteCount)
    } catch {
      throw .secretMemory(error)
    }
    return try SecretBytes(byteCount: validatedCount, initializingWith: initializer)
  }

  private static func constantTimeDifference(
    _ lhs: Span<UInt8>,
    _ rhs: Span<UInt8>
  ) -> UInt32 {
    precondition(lhs.count == rhs.count)
    var difference: UInt32 = 0
    var index = 0
    while index < lhs.count {
      difference |= UInt32(lhs[index] ^ rhs[index])
      index += 1
    }
    return difference
  }
}
