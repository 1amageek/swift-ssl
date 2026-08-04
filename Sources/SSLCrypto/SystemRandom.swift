import SSLCore

/// The random-byte boundary exposed to facade packages.
///
/// Entropy selection remains in SSLCore so platform-specific runtime hooks are
/// owned by one layer. Callers borrow their destination and receive no hidden
/// allocation or intermediate buffer.
public enum SystemRandom {
  public static func fill(
    _ destination: inout MutableSpan<UInt8>
  ) throws(EntropyError) {
    try SystemEntropySource().fill(&destination)
  }
}
