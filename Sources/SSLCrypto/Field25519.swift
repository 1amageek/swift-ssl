/// Ed25519 and X25519 share the prime field 2^255 - 19. Keeping one fixed-size
/// radix-2^51 representation avoids the heap allocation, copy-on-write checks,
/// and repeated normalization previously incurred by Ed25519's `[Int64]`
/// storage. The concrete type owns five initialized UInt64 limbs; no pointer or
/// borrowed storage escapes an arithmetic operation.
typealias Field25519 = X25519FieldElement
