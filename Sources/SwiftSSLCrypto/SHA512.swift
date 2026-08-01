import SwiftSSLCore

public enum SHA512: HashFunction {
  public typealias Context = SHA512Context
  public static let digestByteCount = SHA512Context.digestByteCount
  public static func makeContext() -> SHA512Context { SHA512Context() }
}

public enum SHA384: HashFunction {
  public typealias Context = SHA384Context
  public static let digestByteCount = SHA384Context.digestByteCount
  public static func makeContext() -> SHA384Context { SHA384Context() }
}
