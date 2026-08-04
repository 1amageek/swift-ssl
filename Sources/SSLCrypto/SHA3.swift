import SSLCore

public enum SHA3_256: HashFunction {
  public typealias Context = SHA3_256Context
  public static let digestByteCount = SHA3_256Context.digestByteCount
  public static func makeContext() -> SHA3_256Context { SHA3_256Context() }
}

public enum SHA3_384: HashFunction {
  public typealias Context = SHA3_384Context
  public static let digestByteCount = SHA3_384Context.digestByteCount
  public static func makeContext() -> SHA3_384Context { SHA3_384Context() }
}

public enum SHA3_512: HashFunction {
  public typealias Context = SHA3_512Context
  public static let digestByteCount = SHA3_512Context.digestByteCount
  public static func makeContext() -> SHA3_512Context { SHA3_512Context() }
}
