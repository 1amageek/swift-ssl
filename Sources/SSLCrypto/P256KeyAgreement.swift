import SSLCore

/// Constant-control-flow P-256 ECDH for the RFC 9180 DHKEM profile.
public enum P256KeyAgreement: InPlaceKeyAgreement, InPlaceEncodedKeyAgreement {
  public typealias PublicKey = P256PublicKey
  public typealias PrivateKey = P256PrivateKey
  public typealias SharedSecret = P256SharedSecret

  public static let sharedSecretByteCount = P256SharedSecret.byteCount

  public static func sharedSecret(
    privateKey: borrowing P256PrivateKey,
    peerPublicKey: borrowing P256PublicKey
  ) throws(CryptoInputError) -> P256SharedSecret {
    let byteCount: SecretByteCount
    do {
      byteCount = try SecretByteCount(Self.sharedSecretByteCount)
    } catch {
      preconditionFailure("P-256 shared-secret size is a compile-time constant")
    }
    let secret = try SecretBytes(byteCount: byteCount) { destination throws(CryptoInputError) in
      try sharedSecret(
        privateKey: privateKey,
        peerPublicKey: peerPublicKey,
        into: &destination
      )
    }
    return P256SharedSecret(consuming: secret)
  }

  public static func sharedSecret(
    privateKey: borrowing P256PrivateKey,
    peerPublicKey: borrowing P256PublicKey,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard sharedSecret.count == Self.sharedSecretByteCount else {
      throw .invalidOutputLength(
        expected: Self.sharedSecretByteCount,
        actual: sharedSecret.count
      )
    }
    privateKey.withBorrowedBytes { scalar in
      peerPublicKey.multiplyingSecretScalar(scalar)
        .writeXCoordinateAssumingFinite(into: &sharedSecret)
    }
  }

  public static func sharedSecret(
    privateKey: borrowing P256PrivateKey,
    peerPublicKeyBytes: Span<UInt8>,
    into sharedSecret: inout MutableSpan<UInt8>
  ) throws(CryptoInputError) {
    guard sharedSecret.count == Self.sharedSecretByteCount else {
      throw .invalidOutputLength(
        expected: Self.sharedSecretByteCount,
        actual: sharedSecret.count
      )
    }
    guard let point = P256Point.decodeUncompressed(peerPublicKeyBytes) else {
      throw .invalidPeerKey
    }
    privateKey.withBorrowedBytes { scalar in
      P256Point.scalarMultiplySecret(point, scalar: scalar)
        .writeXCoordinateAssumingFinite(into: &sharedSecret)
    }
  }
}
